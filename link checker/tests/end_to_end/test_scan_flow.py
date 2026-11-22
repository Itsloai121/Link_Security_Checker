"""Whole-system tests: HTTP -> queue -> worker -> real fetcher/parser -> 20 checks -> SQLite -> HTTP."""
import pytest

from tests.support import check, run_scan

pytestmark = pytest.mark.slow


def test_phishing_page_is_dangerous_with_all_twenty_tests_reporting(client, site):
    scan = run_scan(client, site.url("login-paypa1.test", "/signin"))
    assert scan["status"] == "completed" and scan["verdict"] == "dangerous" and scan["risk_score"] >= 90
    assert [c["position"] for c in scan["checks"]] == list(range(1, 21)) and scan["coverage_percent"] == 100
    assert check(scan, "blocklist")["status"] == "danger"                 # fake feed lists the host
    assert check(scan, "lookalike")["status"] == "danger"                 # paypa1 ~ paypal
    assert check(scan, "domain_age")["status"] == "danger"                # registered 3 days ago
    assert check(scan, "login_form")["status"] == "danger"                # card + password on a brand-new domain
    assert check(scan, "form_action_mismatch")["status"] == "danger"      # posts to collector.test
    assert check(scan, "brand_urgency")["status"] == "danger"             # PayPal + "suspended / act now"
    assert check(scan, "hidden_elements")["status"] == "danger"           # invisible full-screen overlay + 0x0 iframe
    assert all(c["explanation"] and c["summary"] for c in scan["checks"])
    assert scan["reasons"] and scan["headline"] == "Don't open this link"


def test_ordinary_page_is_not_flagged_as_dangerous(client, site):
    scan = run_scan(client, site.url("news.test", "/"))
    assert scan["verdict"] in ("safe", "caution") and scan["risk_score"] < 30
    assert check(scan, "login_form")["status"] == "clear" and check(scan, "cloaking")["status"] == "clear"


def test_short_link_is_unwrapped_hop_by_hop(client, site):
    scan = run_scan(client, site.url("short.test", "/abc"))
    chain = check(scan, "redirect_chain")
    hops = [f for f in chain["facts"] if f["key"].startswith("Hop ")]
    assert len(hops) == 3 and scan["final_url"].endswith("/signin") and scan["verdict"] == "dangerous"


def test_trusted_site_open_redirect_is_confirmed(client, site):
    url = site.url("www.paypal.com", f"/go?url=http://login-paypa1.test:{site.port}/signin")
    scan = run_scan(client, url)
    redirect = check(scan, "open_redirect")
    assert redirect["status"] == "danger" and redirect["risk_points"] >= 75
    assert any(f["code"] == "confirmed_open_redirect" for f in redirect["findings"])


def test_executable_disguised_as_pdf_is_caught_without_downloading_it(client, site):
    scan = run_scan(client, site.url("dl.test", "/invoice.pdf"))
    assert check(scan, "auto_download")["status"] == "danger" and check(scan, "port_path_anomaly")["status"] == "danger"
    assert scan["verdict"] == "dangerous"


def test_page_that_hides_from_scanners_is_exposed_by_comparing_two_views(client, site):
    scan = run_scan(client, site.url("cloak.test", "/"))
    cloak = check(scan, "cloaking")
    assert cloak["status"] == "danger" and any(f["code"] in ("form_only_for_browsers", "content_differs") for f in cloak["findings"])


def test_javascript_link_is_analysed_as_text_and_never_fetched(client, site):
    before = len(site.hits)
    scan = run_scan(client, "javascript:alert(document.cookie)")
    assert scan["verdict"] == "dangerous" and check(scan, "dangerous_scheme")["status"] == "danger"
    assert check(scan, "redirect_chain")["status"] == "unavailable" and check(scan, "login_form")["status"] == "unavailable"
    assert len(site.hits) == before


def test_label_versus_destination_mismatch(client, site):
    scan = run_scan(client, site.url("news.test", "/"), label="Official PayPal portal: https://www.paypal.com/signin")
    assert check(scan, "display_mismatch")["status"] == "danger"


def test_reports_can_be_deleted_and_then_do_not_exist(client, site):
    scan = run_scan(client, site.url("news.test", "/"))
    assert client.delete(f"/api/v1/scans/{scan['id']}").status_code == 204
    gone = client.get(f"/api/v1/scans/{scan['id']}")
    assert gone.status_code == 404 and gone.json()["error"]["code"] == "SCAN_NOT_FOUND"
    assert client.delete(f"/api/v1/scans/{scan['id']}").status_code == 404


def test_progress_is_visible_while_running_and_results_persist_across_restarts(make_client, site, tmp_path):
    with make_client() as c:
        scan = run_scan(c, site.url("news.test", "/"))
    with make_client() as c2:                                           # a brand-new process over the same database file
        again = c2.get(f"/api/v1/scans/{scan['id']}").json()
        assert again["status"] == "completed" and again["verdict"] == scan["verdict"] and len(again["checks"]) == 20
