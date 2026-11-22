import pytest

from modules.link_analysis.domain.checks.base import CheckResult, CheckStatus, Severity, build_result, CheckSpec, Category, Outcome, fnd
from modules.link_analysis.domain.checks.catalog import ALL_CHECKS, EXPECTED_CHECKS
from modules.link_analysis.domain.scan import Scan, ScanStatus, Verdict
from modules.link_analysis.domain.scoring import assess
from shared.errors import BusinessRuleViolation
from tests.unit.conftest import NOW


def result(i, status=CheckStatus.CLEAR, *findings):
    return CheckResult(f"c{i}", i, status, 0, "s", tuple(findings))


def twenty(**overrides):
    out = [result(i) for i in range(1, 21)]
    for i, r in overrides.items():
        out[int(i[1:]) - 1] = r
    return out


def test_catalog_matches_the_brief():
    assert EXPECTED_CHECKS == 20 and [c.spec.position for c in ALL_CHECKS] == list(range(1, 21))
    assert ALL_CHECKS[0].spec.title.startswith("Threat & Phishing") and ALL_CHECKS[-1].spec.title.startswith("Final Destination")
    assert all(len(c.spec.explanation) > 40 for c in ALL_CHECKS)           # every point carries an explanation


def test_all_clear_with_page_is_safe_but_without_page_is_inconclusive():
    base = twenty(c14=CheckResult("login_form", 14, CheckStatus.CLEAR, 0, "s"))
    assert assess(base, web_link=True).verdict is Verdict.SAFE
    no_page = twenty(c14=CheckResult("login_form", 14, CheckStatus.UNAVAILABLE, 0, "s"))
    assert assess(no_page, web_link=True).verdict is Verdict.INCONCLUSIVE   # never 'safe' when the page was not inspected


def test_one_critical_finding_means_dangerous():
    crit = CheckResult("blocklist", 1, CheckStatus.DANGER, 75, "listed", (fnd(Severity.CRITICAL, "listed", "Listed as phishing"),))
    a = assess(twenty(c1=crit), web_link=True)
    assert a.verdict is Verdict.DANGEROUS and a.risk_score >= 75 and a.reasons == ("Listed as phishing",)


def test_findings_accumulate_but_cap_at_100():
    highs = [CheckResult(f"c{i}", i, CheckStatus.DANGER, 35, "x", (fnd(Severity.HIGH, f"h{i}", f"m{i}"),)) for i in range(1, 9)]
    assert assess(highs + [result(i) for i in range(9, 21)], web_link=True).risk_score <= 100
    two = twenty(c1=highs[0], c2=highs[1])
    assert assess(two, web_link=True).verdict is Verdict.SUSPICIOUS


def test_unavailable_never_scores_as_risk_or_as_safe():
    a = assess([CheckResult(f"c{i}", i, CheckStatus.UNAVAILABLE, 0, "x") for i in range(1, 21)], web_link=True)
    assert a.risk_score == 0 and a.verdict is Verdict.INCONCLUSIVE and a.coverage_percent == 0


def test_build_result_bounds_and_status():
    spec = CheckSpec("x", 1, "X", Category.ADDRESS, "e")
    big = Outcome.flagged([fnd(Severity.HIGH, f"c{i}", "m" * 900) for i in range(30)])
    r = build_result(spec, big, 5)
    assert len(r.findings) <= 12 and all(len(f.message) <= 500 for f in r.findings) and r.status is CheckStatus.DANGER and r.risk_points == 100
    assert build_result(spec, Outcome.missing("why"), 1).status is CheckStatus.UNAVAILABLE


def test_scan_lifecycle_is_enforced():
    from datetime import timedelta
    s = Scan("a" * 22, "https://a.example", None, ScanStatus.QUEUED, NOW, NOW + timedelta(hours=1), "1")
    with pytest.raises(BusinessRuleViolation):
        s.record_result(result(1))                      # not running yet
    s.start(NOW, "https://a.example/")
    s.record_result(result(1))
    with pytest.raises(BusinessRuleViolation):
        s.complete(NOW, verdict=Verdict.SAFE, risk_score=0, coverage_percent=100, headline="h", reasons=[], final_url=None, expected_checks=20)  # incomplete
    for i in range(2, 21):
        s.record_result(result(i))
    s.complete(NOW, verdict=Verdict.SAFE, risk_score=0, coverage_percent=100, headline="h", reasons=[], final_url=None, expected_checks=20)
    with pytest.raises(BusinessRuleViolation):
        s.fail(NOW, "X")                                # terminal state
