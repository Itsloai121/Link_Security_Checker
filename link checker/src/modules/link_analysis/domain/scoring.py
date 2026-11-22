"""Turns 20 check results into one verdict. Transparent and deterministic: noisy-OR over finding points."""
from __future__ import annotations

from dataclasses import dataclass
from collections.abc import Sequence

from modules.link_analysis.domain.checks.base import POINTS, CheckResult, CheckStatus, Severity
from modules.link_analysis.domain.scan import Verdict

HEADLINES = {
    Verdict.SAFE: "No threats found",
    Verdict.CAUTION: "A few warning signs",
    Verdict.SUSPICIOUS: "This link looks suspicious",
    Verdict.DANGEROUS: "Don't open this link",
    Verdict.INCONCLUSIVE: "We couldn't verify this link",
}
THRESHOLDS = (("safe", 10), ("caution", 30), ("suspicious", 65))  # score < bound -> verdict
# Among equally severe findings, lead the summary with the most telling evidence (lower = earlier).
PRIORITY = {"listed": 0, "serves_executable": 1, "disguised_file": 1, "doc_is_program": 1, "seed_phrase": 2, "decoy_userinfo": 3, "confirmed_open_redirect": 4,
            "brand_homograph": 5, "exfil_action": 6, "cross_domain_secret": 6, "ip_action": 6, "brand_login": 7, "brand_plus_pressure": 8, "new_domain_login": 9,
            "swapped_characters": 10, "wrong_domain": 10, "embedded_domain": 11, "trusted_to_unknown": 11, "label_domain_mismatch": 12, "different_destination": 13,
            "form_only_for_browsers": 13, "invisible_overlay": 20, "brand_new": 21, "no_https": 30}


@dataclass(frozen=True)
class Assessment:
    verdict: Verdict
    risk_score: int
    coverage_percent: int
    headline: str
    reasons: tuple[str, ...]
    flagged: int
    clear: int
    unverified: int


def assess(results: Sequence[CheckResult], *, web_link: bool) -> Assessment:
    findings = [(f, r) for r in results for f in r.findings if f.severity >= Severity.LOW]
    survive = 1.0
    for f, _ in findings:
        survive *= 1 - POINTS[f.severity] / 100
    score = round(100 * (1 - survive))
    total = max(1, len(results))
    unverified = sum(1 for r in results if r.status is CheckStatus.UNAVAILABLE)
    coverage = round(100 * (total - unverified) / total)
    flagged = sum(1 for r in results if r.status in (CheckStatus.NOTICE, CheckStatus.WARNING, CheckStatus.DANGER))
    clear = sum(1 for r in results if r.status is CheckStatus.CLEAR)

    if any(f.severity is Severity.CRITICAL for f, _ in findings) or score >= 65:
        verdict = Verdict.DANGEROUS
    elif score >= 30:
        verdict = Verdict.SUSPICIOUS
    elif score >= 10:
        verdict = Verdict.CAUTION
    else:
        verdict = Verdict.SAFE
    page_checked = any(r.check_id == "login_form" and r.status is not CheckStatus.UNAVAILABLE for r in results)
    if verdict is Verdict.SAFE and (coverage < 70 or (web_link and not page_checked)):
        verdict = Verdict.INCONCLUSIVE

    top = sorted(findings, key=lambda t: (-t[0].severity, PRIORITY.get(t[0].code, 50)))
    reasons: list[str] = []
    for f, _ in top:
        if f.message not in reasons:
            reasons.append(f.message)
        if len(reasons) == 3:
            break
    return Assessment(verdict, score, coverage, HEADLINES[verdict], tuple(reasons), flagged, clear, unverified)
