"""Security regression tests mapped to docs/architecture/security.md. Each test names the threat it guards against."""
import re
from pathlib import Path

import pytest

from tests.support import check, run_scan

WEB = Path(__file__).resolve().parents[2] / "src" / "interfaces" / "web"
PAGES = sorted((WEB / "pages").glob("*.html"))
SCRIPTS = sorted(p for d in ("components", "pages", "state", "api_client") for p in (WEB / d).glob("*.js"))


# ---- SSRF: the scanner must never become a proxy into private networks ---------------------------------------------------
@pytest.mark.parametrize("target", ["http://127.0.0.1:{port}/", "http://[::1]:{port}/", "http://169.254.169.254/latest/meta-data/", "http://3232235777/",
                                    "http://0x7f.1:{port}/", "http://localhost:{port}/", "http://10.0.0.5/admin"])
def test_internal_targets_are_refused_and_never_contacted(make_client, site, target):
    before = len(site.hits)
    with make_client(allow_private_networks=False, rate_limit_submit_per_minute=100) as c:
        scan = run_scan(c, target.format(port=site.port))
    assert scan["status"] == "completed" and check(scan, "redirect_chain")["status"] == "unavailable"
    assert check(scan, "login_form")["status"] == "unavailable"
    assert len(site.hits) == before                                                     # not a single request reached the fixture server
    assert scan["verdict"] in ("dangerous", "suspicious", "inconclusive")               # never 'safe'


def test_a_public_looking_name_that_resolves_to_a_private_address_is_blocked(make_client, site):
    """DNS-rebinding / split-horizon: the hostname is harmless-looking, the answer is 127.0.0.1."""
    before = len(site.hits)
    with make_client(allow_private_networks=False) as c:
        scan = run_scan(c, site.url("news.test", "/"))
    assert check(scan, "hosting_risk")["status"] == "danger" and len(site.hits) == before
    assert any(f["code"] == "internal_address" for f in check(scan, "hosting_risk")["findings"])


# ---- input abuse and denial of service ---------------------------------------------------------------------------------
def test_rate_limit_per_client_with_retry_after(make_client):
    with make_client(rate_limit_submit_per_minute=3) as c:
        codes = [c.post("/api/v1/scans", json={"url": f"javascript:{i}"}).status_code for i in range(5)]
        last = c.post("/api/v1/scans", json={"url": "javascript:9"})
    assert codes == [202, 202, 202, 429, 429] and last.json()["error"]["code"] == "RATE_LIMITED" and int(last.headers["Retry-After"]) >= 1


def test_one_victim_site_cannot_be_hammered_through_the_scanner(make_client, site):
    with make_client(rate_limit_submit_per_minute=100, per_host_scans_per_minute=2) as c:
        codes = [c.post("/api/v1/scans", json={"url": site.url("news.test", f"/{i}")}).status_code for i in range(4)]
    assert codes == [202, 202, 429, 429]


def test_queue_full_is_reported_not_silently_dropped(make_client, site):
    with make_client(queue_size=1, worker_concurrency=1, rate_limit_submit_per_minute=100, per_host_scans_per_minute=100) as c:
        codes = [c.post("/api/v1/scans", json={"url": site.url("news.test", f"/{i}")}).status_code for i in range(12)]
    assert 503 in codes and 202 in codes


# ---- browser-side defences ---------------------------------------------------------------------------------------------
@pytest.mark.parametrize("path", ["/", "/process", "/analysis", "/api/v1/checks", "/api/v1/health/live", "/assets/images/favicon.svg", "/api/nope"])
def test_security_headers_everywhere_including_errors(client, path):
    h = client.get(path).headers
    csp = h["Content-Security-Policy"]
    assert "default-src 'none'" in csp and "script-src 'self'" in csp and "frame-ancestors 'none'" in csp and "unsafe-inline" not in csp and "unsafe-eval" not in csp
    assert h["X-Content-Type-Options"] == "nosniff" and h["X-Frame-Options"] == "DENY" and h["Referrer-Policy"] == "no-referrer"
    assert "server" not in {k.lower() for k in h} or "uvicorn" not in h.get("server", "").lower()
    if path.startswith("/api/"):
        assert h["Cache-Control"] in ("no-store", "public, max-age=3600")


@pytest.mark.parametrize("page", PAGES, ids=lambda p: p.name)
def test_pages_have_no_inline_script_style_or_event_handlers(page):
    html = page.read_text(encoding="utf-8")
    assert not re.search(r"<script(?![^>]*\bsrc=)[^>]*>", html), "inline <script> would violate CSP"
    assert not re.search(r"\sstyle\s*=", html) and not re.search(r"<style", html), "inline style would violate CSP"
    assert not re.search(r"\son[a-z]+\s*=", html, re.I), "inline event handler would violate CSP"
    assert not re.search(r"""(?:src|href)=["']https?://""", html), "no third-party resources: fonts, scripts and images are self-hosted"
    assert 'lang="en"' in html and 'id="main"' in html and "skip-link" in html


@pytest.mark.parametrize("js", SCRIPTS, ids=lambda p: p.name)
def test_javascript_never_renders_untrusted_data_as_html(js):
    code = js.read_text(encoding="utf-8")
    for banned in (r"\.innerHTML", r"\.outerHTML", r"insertAdjacentHTML", r"document\.write", r"\beval\(", r"new Function", r"setAttribute\(\s*['\"]style", r"\.cssText"):
        assert not re.search(banned, code), f"{js.name} uses {banned}: report data comes from hostile pages and must go through textContent only"
    assert not re.search(r"https?://(?!www\.w3\.org)", code), "no external hosts referenced from scripts"


def test_css_makes_no_external_requests():
    for css in (WEB / "styles").glob("*.css"):
        assert not re.search(r"url\(\s*['\"]?https?://", css.read_text()), css.name


# ---- hostile page content must stay inert ---------------------------------------------------------------------------------
def test_markup_from_analysed_pages_is_returned_as_inert_json_text(make_client, site):
    with make_client() as c:
        scan = run_scan(c, "https://x.example/%3Cscript%3Ealert(1)%3C/script%3E?q=<img src=x onerror=alert(1)>")
        raw = c.get(f"/api/v1/scans/{scan['id']}")
    assert raw.headers["Content-Type"].startswith("application/json") and raw.headers["X-Content-Type-Options"] == "nosniff"


# ---- privacy: logs and metrics never contain what was submitted ---------------------------------------------------------
def test_submitted_paths_queries_and_credentials_never_reach_the_logs(make_client, site, capsys):
    secret = "SECRET-TOKEN-9f3a"
    with make_client(log_level="INFO") as c:        # the app writes JSON logs to stdout; read them exactly as an operator would
        scan = run_scan(c, f"https://user:{secret}@news.test:{site.port}/reset/{secret}?token={secret}#{secret}")
        c.get(f"/api/v1/scans/{scan['id']}")
    logs = capsys.readouterr().out
    assert '"event": "scan_submitted"' in logs and '"event": "scan_completed"' in logs and "news.test" in logs      # useful events are logged...
    assert secret not in logs and "reset/" not in logs and "token=" not in logs                                      # ...without the sensitive parts


# ---- operational endpoints -------------------------------------------------------------------------------------------------
def test_metrics_endpoint_is_hidden_unless_a_token_is_configured_and_supplied(make_client):
    with make_client() as c:
        assert c.get("/internal/metrics").status_code == 404
    with make_client(metrics_token="s3cret-token") as c:
        assert c.get("/internal/metrics").status_code == 404
        assert c.get("/internal/metrics", headers={"Authorization": "Bearer wrong"}).status_code == 404
        ok = c.get("/internal/metrics", headers={"Authorization": "Bearer s3cret-token"})
        assert ok.status_code == 200 and "unmask_http_requests_total" in ok.text and "s3cret" not in ok.text


def test_api_docs_are_not_exposed_in_production(make_client):
    with make_client(environment="production", allow_private_networks=False) as c:
        assert c.get("/api/docs").status_code == 404 and c.get("/api/openapi.json").status_code == 404
    with make_client() as c:
        assert c.get("/api/docs").status_code == 200


def test_scan_ids_are_unguessable_and_unique(client):
    ids = {client.post("/api/v1/scans", json={"url": f"javascript:{i}"}).json()["id"] for i in range(30)}
    assert len(ids) == 30 and all(re.fullmatch(r"[A-Za-z0-9_-]{22}", i) for i in ids)


def test_static_files_cannot_escape_their_directory(client):
    for path in ("/static/styles/../../../../etc/passwd", "/assets/../../pyproject.toml", "/static/pages/..%2f..%2f..%2fpyproject.toml", "/static/components/%2e%2e/%2e%2e/bootstrap/settings.py"):
        assert client.get(path).status_code in (404, 400, 403)


# ---- display spoofing: hidden bidi / zero-width characters must be made visible in the UI -----------------------------------
def test_ui_funnels_all_visible_text_through_safe_text():
    helper = (WEB / "components" / "safe-text.js").read_text()
    assert r"\u202a-\u202e" in helper and r"\u2066-\u2069" in helper and r"\u200b-\u200f" in helper
    assert "safeText(" in (WEB / "components" / "dom.js").read_text()                       # every h(..., text) and text child
    assert "safeText(scan.submitted_input)" in (WEB / "components" / "verdict-panel.js").read_text()
    assert "safeText(text)" in (WEB / "components" / "typing.js").read_text()
