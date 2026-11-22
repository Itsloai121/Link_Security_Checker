"""Translate between HTTP-shaped data and application use cases. No business rules live here (USBA §4.2)."""
from __future__ import annotations

import hashlib

from bootstrap.dependency_wiring import Container
from interfaces.api.schemas.scans import (CheckCatalogItem, CheckCatalogOut, CheckResultOut, Counts, FindingOut, KeyValue, Progress, ScanOut,
                                          SubmitScanRequest)
from modules.link_analysis.application.submit_link import SubmitLink
from modules.link_analysis.domain.checks.base import CheckResult, CheckStatus
from modules.link_analysis.domain.checks.catalog import CATEGORY_LABELS, EXPECTED_CHECKS, specs
from modules.link_analysis.domain.scan import Scan
from modules.link_analysis.domain.url_model import parse_url
from shared.errors import RateLimited

_SPECS = {s.id: s for s in specs()}


def client_key(peer: str | None, forwarded_for: str | None, trusted_hops: int) -> str:
    """Rate-limit identity. X-Forwarded-For is honoured only when the operator declares how many proxies sit in front."""
    ip = peer or "unknown"
    if trusted_hops > 0 and forwarded_for:
        parts = [p.strip() for p in forwarded_for.split(",") if p.strip()]
        if len(parts) >= trusted_hops:
            ip = parts[-trusted_hops]
    return hashlib.blake2s(ip.encode(), digest_size=8).hexdigest()  # keyed on a hash: raw addresses are never stored


def check_out(r: CheckResult) -> CheckResultOut:
    spec = _SPECS[r.check_id]
    return CheckResultOut(
        id=r.check_id, position=r.position, title=spec.title, category=spec.category.value, category_label=CATEGORY_LABELS[spec.category.value],
        explanation=spec.explanation, status=r.status.value, risk_points=r.risk_points, summary=r.summary,
        findings=[FindingOut(severity=f.severity.name.lower(), code=f.code, message=f.message, evidence=[KeyValue(key=k, value=v) for k, v in f.evidence]) for f in r.findings],
        facts=[KeyValue(key=k, value=v) for k, v in r.facts], limitation=r.limitation, duration_ms=r.duration_ms)


def scan_out(scan: Scan) -> ScanOut:
    results = sorted(scan.results, key=lambda r: r.position)
    flagged = sum(1 for r in results if r.status in (CheckStatus.NOTICE, CheckStatus.WARNING, CheckStatus.DANGER))
    return ScanOut(
        id=scan.id, status=scan.status.value, submitted_input=scan.submitted_input, display_text=scan.display_text, normalized_url=scan.normalized_url,
        final_url=scan.final_url, verdict=scan.verdict.value if scan.verdict else None, headline=scan.headline, reasons=scan.reasons,
        risk_score=scan.risk_score, coverage_percent=scan.coverage_percent, progress=Progress(done=len(results), total=EXPECTED_CHECKS),
        counts=Counts(flagged=flagged, clear=sum(1 for r in results if r.status is CheckStatus.CLEAR), unverified=sum(1 for r in results if r.status is CheckStatus.UNAVAILABLE)),
        created_at=scan.created_at, expires_at=scan.expires_at, completed_at=scan.completed_at, error_code=scan.error_code, engine_version=scan.engine_version,
        checks=[check_out(r) for r in results])


async def submit_scan(c: Container, payload: SubmitScanRequest, key: str) -> ScanOut:
    ok, retry = c.submit_limiter.check(key)
    if not ok:
        c.metrics.inc("unmask_rate_limited_total", {"scope": "submit"})
        raise RateLimited(retry)
    target = parse_url(payload.url)
    if target.is_web and target.registrable:  # stops the scanner being used to hammer one victim site
        ok, retry = c.host_limiter.check(target.registrable)
        if not ok:
            c.metrics.inc("unmask_rate_limited_total", {"scope": "per_host"})
            raise RateLimited(retry, "That site was just checked several times. Please wait a minute before checking it again.")
    scan = await c.submit_link.execute(SubmitLink(payload.url, payload.display_text))
    return scan_out(scan)


async def get_scan(c: Container, scan_id: str, key: str) -> ScanOut:
    ok, retry = c.read_limiter.check(key)
    if not ok:
        c.metrics.inc("unmask_rate_limited_total", {"scope": "read"})
        raise RateLimited(retry)
    return scan_out(await c.get_scan.execute(scan_id))


async def delete_scan(c: Container, scan_id: str, key: str) -> None:
    ok, retry = c.read_limiter.check(key)
    if not ok:
        raise RateLimited(retry)
    await c.delete_scan.execute(scan_id)


def check_catalog(c: Container) -> CheckCatalogOut:
    return CheckCatalogOut(
        checks=[CheckCatalogItem(id=s.id, position=s.position, title=s.title, category=s.category.value, category_label=CATEGORY_LABELS[s.category.value], explanation=s.explanation)
                for s in c.list_checks.execute()], categories=CATEGORY_LABELS)
