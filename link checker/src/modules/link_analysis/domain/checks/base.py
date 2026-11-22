"""Check framework. A check is a PURE function of (parsed URL, optional display text, evidence, reference data)."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from enum import IntEnum, StrEnum
from typing import Protocol
from collections.abc import Mapping

from modules.link_analysis.domain.evidence import Evidence
from modules.link_analysis.domain.reference import ReferenceData
from modules.link_analysis.domain.url_model import ParsedUrl

MAX_FINDINGS, MAX_FACTS, MAX_TEXT = 12, 16, 400


class Category(StrEnum):
    ADDRESS = "address"        # what the address itself is hiding
    JOURNEY = "journey"        # where the link really goes
    REPUTATION = "reputation"  # who is behind it
    BEHAVIOR = "behavior"      # what the destination page does


class Severity(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


POINTS = {Severity.INFO: 0, Severity.LOW: 5, Severity.MEDIUM: 15, Severity.HIGH: 35, Severity.CRITICAL: 75}


class CheckStatus(StrEnum):
    CLEAR = "clear"
    NOTICE = "notice"
    WARNING = "warning"
    DANGER = "danger"
    UNAVAILABLE = "unavailable"


KV = tuple[tuple[str, str], ...]


def _clip(value: object, limit: int = MAX_TEXT) -> str:
    s = str(value)
    return s if len(s) <= limit else s[: limit - 1] + "…"


def kv(**pairs: object) -> KV:
    """kv(Matched_brand='PayPal') -> (('Matched brand', 'PayPal'),). Values are clipped: evidence can be attacker-controlled."""
    return tuple((k.replace("_", " "), _clip(v)) for k, v in pairs.items() if v is not None and v != "")


@dataclass(frozen=True)
class Finding:
    severity: Severity
    code: str
    message: str
    evidence: KV = ()


def fnd(severity: Severity, code: str, message: str, **evidence: object) -> Finding:
    return Finding(severity, code, _clip(message, 500), kv(**evidence))


@dataclass(frozen=True)
class CheckSpec:
    id: str
    position: int
    title: str
    category: Category
    explanation: str            # what the test does - shown next to every result
    requires: frozenset[str] = frozenset()


@dataclass(frozen=True)
class Outcome:
    findings: tuple[Finding, ...] = ()
    facts: KV = ()
    summary: str | None = None
    unavailable: str | None = None
    limitation: str | None = None

    @staticmethod
    def clear(summary: str, limitation: str | None = None, **facts: object) -> "Outcome":
        return Outcome((), kv(**facts), summary, None, limitation)

    @staticmethod
    def flagged(findings: list[Finding], summary: str | None = None, limitation: str | None = None, **facts: object) -> "Outcome":
        return Outcome(tuple(findings), kv(**facts), summary, None, limitation)

    @staticmethod
    def missing(reason: str) -> "Outcome":
        return Outcome(unavailable=reason)


@dataclass(frozen=True)
class CheckResult:
    check_id: str
    position: int
    status: CheckStatus
    risk_points: int
    summary: str
    findings: tuple[Finding, ...] = ()
    facts: KV = ()
    limitation: str | None = None
    duration_ms: int = 0


@dataclass(frozen=True)
class CheckContext:
    url: ParsedUrl
    display_text: str | None
    ref: ReferenceData
    now: datetime
    evidence_map: Mapping[str, Evidence]
    allowed: frozenset[str]

    def evidence(self, key: str) -> Evidence:
        if key not in self.allowed:
            raise KeyError(f"check did not declare evidence '{key}'")
        return self.evidence_map.get(key, Evidence.missing("not collected"))


class Check(Protocol):
    spec: CheckSpec

    def evaluate(self, ctx: CheckContext) -> Outcome: ...


def status_for(findings: tuple[Finding, ...]) -> CheckStatus:
    top = max((f.severity for f in findings), default=Severity.INFO)
    if top >= Severity.HIGH:
        return CheckStatus.DANGER
    if top == Severity.MEDIUM:
        return CheckStatus.WARNING
    if top == Severity.LOW:
        return CheckStatus.NOTICE
    return CheckStatus.CLEAR


def build_result(spec: CheckSpec, outcome: Outcome, duration_ms: int) -> CheckResult:
    if outcome.unavailable is not None:
        return CheckResult(spec.id, spec.position, CheckStatus.UNAVAILABLE, 0, _clip(outcome.unavailable, 300), (), (), None, duration_ms)
    ordered = tuple(sorted(outcome.findings, key=lambda f: -f.severity))[:MAX_FINDINGS]
    status = status_for(ordered)
    points = min(100, sum(POINTS[f.severity] for f in ordered))
    summary = outcome.summary or (ordered[0].message if ordered else "Nothing suspicious found.")
    if ordered and ordered[0].severity >= Severity.LOW and outcome.summary is None:
        summary = ordered[0].message
    return CheckResult(spec.id, spec.position, status, points, _clip(summary, 300), ordered, outcome.facts[:MAX_FACTS], outcome.limitation, duration_ms)
