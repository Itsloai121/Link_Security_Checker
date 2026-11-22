"""The analysis workflow (USBA §3 use case): collect evidence, evaluate 20 checks, persist progress, decide the verdict."""
from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Sequence

from infrastructure.observability.logging import event, scan_id_var
from infrastructure.observability.metrics import Metrics
from modules.link_analysis.application.evidence_collector import EvidenceCollector
from modules.link_analysis.application.settings import AnalysisPolicy
from modules.link_analysis.domain.checks.base import Check, CheckContext, CheckResult, Outcome, build_result
from modules.link_analysis.domain.checks.catalog import ALL_CHECKS, EXPECTED_CHECKS
from modules.link_analysis.domain.reference import ReferenceData
from modules.link_analysis.domain.scan import Scan, ScanStatus
from modules.link_analysis.domain.scoring import assess
from modules.link_analysis.domain.url_model import parse_url
from modules.link_analysis.ports.scan_repository import ScanRepository
from shared.contracts.clock import Clock

log = logging.getLogger("unmask.analysis")


class RunLinkAnalysis:
    def __init__(self, repo: ScanRepository, collector: EvidenceCollector, reference: ReferenceData, clock: Clock, policy: AnalysisPolicy,
                 metrics: Metrics, checks: Sequence[Check] = ALL_CHECKS):
        self.repo, self.collector, self.ref, self.clock, self.policy, self.metrics, self.checks = repo, collector, reference, clock, policy, metrics, checks

    async def execute(self, scan_id: str) -> None:
        scan_id_var.set(scan_id)
        scan = await self.repo.get(scan_id)
        if scan is None or scan.status is not ScanStatus.QUEUED:
            return  # deleted, expired, or already handled: jobs are idempotent
        started = time.monotonic()
        url = parse_url(scan.submitted_input)
        try:
            scan.start(self.clock.now(), url.fetch_url if url.is_web else url.display_url)
            await self.repo.save(scan)
            session = self.collector.start(url)
            try:
                async with asyncio.timeout(self.policy.scan_deadline_seconds):
                    await asyncio.gather(*(self._run_check(c, scan, url, session) for c in self.checks))
            except TimeoutError:
                event(log, "scan_deadline_reached", logging.WARNING, done=len(scan.results))
            finally:
                session.cancel()
            for c in self.checks:  # anything that did not finish is reported as NOT VERIFIED, never as safe
                if not any(r.check_id == c.spec.id for r in scan.results):
                    await self._record(scan, build_result(c.spec, Outcome.missing("This test ran out of time before it finished."), 0))
            ordered = sorted(scan.results, key=lambda r: r.position)
            a = assess(ordered, web_link=url.is_web)
            j = session.peek("journey")
            final_url = j.value.final_url if j.available else None
            scan.complete(self.clock.now(), verdict=a.verdict, risk_score=a.risk_score, coverage_percent=a.coverage_percent, headline=a.headline,
                          reasons=list(a.reasons), final_url=final_url, expected_checks=EXPECTED_CHECKS)
            await self.repo.save(scan)
            self.metrics.inc("unmask_scans_completed_total", {"verdict": a.verdict.value})
            self.metrics.observe("unmask_scan_duration_seconds", time.monotonic() - started)
            event(log, "scan_completed", verdict=a.verdict.value, score=a.risk_score, coverage=a.coverage_percent, duration_ms=int((time.monotonic() - started) * 1000))
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            event(log, "scan_failed", logging.ERROR, exc_type=type(exc).__name__)
            self.metrics.inc("unmask_scans_failed_total")
            if scan.status in (ScanStatus.QUEUED, ScanStatus.RUNNING):
                scan.fail(self.clock.now(), "INTERNAL_ERROR")
                await self.repo.save(scan)

    async def _run_check(self, check: Check, scan: Scan, url, session) -> None:
        t0 = time.monotonic()
        evidence = {key: await session.get(key) for key in check.spec.requires}
        ctx = CheckContext(url, scan.display_text, self.ref, self.clock.now(), evidence, check.spec.requires)
        try:
            outcome = check.evaluate(ctx)
        except Exception as exc:  # a bug in one check must never take down the scan
            event(log, "check_crashed", logging.ERROR, check=check.spec.id, exc_type=type(exc).__name__)
            self.metrics.inc("unmask_check_failures_total", {"check": check.spec.id})
            outcome = Outcome.missing("This test hit an internal error and could not complete.")
        result = build_result(check.spec, outcome, int((time.monotonic() - t0) * 1000))
        self.metrics.inc("unmask_checks_total", {"check": check.spec.id, "status": result.status.value})
        await self._record(scan, result)

    async def _record(self, scan: Scan, result: CheckResult) -> None:
        scan.record_result(result)
        await self.repo.save_result(scan.id, result)
