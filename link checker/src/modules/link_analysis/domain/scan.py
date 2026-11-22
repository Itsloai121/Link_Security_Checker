"""The Scan aggregate: one submitted link and its analysis, with a guarded lifecycle (USDA §5.1, §7.1 state transitions)."""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import StrEnum

from modules.link_analysis.domain.checks.base import CheckResult
from shared.errors import BusinessRuleViolation


EXPECTED_CHECK_COUNT = 20  # asserted against the catalogue in checks/catalog.py


class ScanStatus(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class Verdict(StrEnum):
    SAFE = "safe"
    CAUTION = "caution"
    SUSPICIOUS = "suspicious"
    DANGEROUS = "dangerous"
    INCONCLUSIVE = "inconclusive"


_ALLOWED = {
    ScanStatus.QUEUED: {ScanStatus.RUNNING, ScanStatus.FAILED},
    ScanStatus.RUNNING: {ScanStatus.COMPLETED, ScanStatus.FAILED},
    ScanStatus.COMPLETED: set(),
    ScanStatus.FAILED: set(),
}


@dataclass
class Scan:
    id: str
    submitted_input: str
    display_text: str | None
    status: ScanStatus
    created_at: datetime
    expires_at: datetime
    engine_version: str
    normalized_url: str | None = None
    final_url: str | None = None
    verdict: Verdict | None = None
    risk_score: int | None = None
    coverage_percent: int | None = None
    headline: str | None = None
    reasons: list[str] = field(default_factory=list)
    error_code: str | None = None
    started_at: datetime | None = None
    completed_at: datetime | None = None
    results: list[CheckResult] = field(default_factory=list)

    def _move(self, target: ScanStatus) -> None:
        if target not in _ALLOWED[self.status]:
            raise BusinessRuleViolation(f"A scan cannot go from {self.status.value} to {target.value}.", "INVALID_SCAN_TRANSITION")
        self.status = target

    def start(self, now: datetime, normalized_url: str | None) -> None:
        self._move(ScanStatus.RUNNING)
        self.started_at, self.normalized_url = now, normalized_url

    def record_result(self, result: CheckResult) -> None:
        if self.status is not ScanStatus.RUNNING:
            raise BusinessRuleViolation("Results can only be recorded while a scan is running.", "SCAN_NOT_RUNNING")
        self.results = [r for r in self.results if r.check_id != result.check_id] + [result]

    def complete(self, now: datetime, *, verdict: Verdict, risk_score: int, coverage_percent: int, headline: str,
                 reasons: list[str], final_url: str | None, expected_checks: int) -> None:
        if len({r.check_id for r in self.results}) != expected_checks:
            raise BusinessRuleViolation("A scan can only complete once every check has reported.", "SCAN_INCOMPLETE")
        self._move(ScanStatus.COMPLETED)
        self.verdict, self.risk_score, self.coverage_percent = verdict, risk_score, coverage_percent
        self.headline, self.reasons, self.final_url, self.completed_at = headline, reasons, final_url, now

    def fail(self, now: datetime, error_code: str) -> None:
        self._move(ScanStatus.FAILED)
        self.error_code, self.completed_at = error_code, now

    @property
    def progress(self) -> tuple[int, int]:
        return len(self.results), EXPECTED_CHECK_COUNT
