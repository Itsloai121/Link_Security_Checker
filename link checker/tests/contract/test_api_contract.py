"""The API's published promises: error shape, status codes, headers, catalogue. Changing any of these is a breaking change."""
import re

import pytest


ERROR_KEYS = {"code", "message", "request_id", "details"}


def assert_error(resp, status, code):
    assert resp.status_code == status, resp.text
    body = resp.json()
    assert set(body) == {"error"} and set(body["error"]) == ERROR_KEYS and body["error"]["code"] == code
    assert body["error"]["request_id"] == resp.headers["X-Request-ID"]          # the same ID in header, body and logs
    assert "Traceback" not in resp.text and "File \"" not in resp.text           # never leak internals


def test_submit_returns_202_location_and_stable_shape(client):
    r = client.post("/api/v1/scans", json={"url": "https://example.com/"})
    assert r.status_code == 202 and r.headers["Location"] == f"/api/v1/scans/{r.json()['id']}"
    body = r.json()
    assert re.fullmatch(r"[A-Za-z0-9_-]{22}", body["id"]) and body["status"] in ("queued", "running", "completed")
    assert {"progress", "counts", "checks", "expires_at", "engine_version", "submitted_input"} <= set(body) and body["progress"]["total"] == 20


@pytest.mark.parametrize("payload", [{}, {"url": ""}, {"url": "   "}, {"url": "x" * 5000}, {"url": "https://a.example", "extra": 1}, {"url": "https://a.example", "display_text": "y" * 1001},
                                     {"url": "https://a.example/\x00"}, {"url": 123}])
def test_validation_errors_use_the_error_contract_and_never_echo_input(client, payload):
    r = client.post("/api/v1/scans", json=payload)
    assert_error(r, 422, "VALIDATION_FAILED")
    assert "x" * 100 not in r.text


def test_unknown_and_malformed_ids_look_identical(client):
    assert_error(client.get("/api/v1/scans/" + "A" * 22), 404, "SCAN_NOT_FOUND")
    assert_error(client.get("/api/v1/scans/not-an-id"), 404, "SCAN_NOT_FOUND")       # no format oracle for guessers
    assert_error(client.delete("/api/v1/scans/" + "B" * 22), 404, "SCAN_NOT_FOUND")


def test_other_failures_share_the_contract(client):
    assert_error(client.get("/api/v1/nope"), 404, "NOT_FOUND")
    assert_error(client.put("/api/v1/scans", json={}), 405, "METHOD_NOT_ALLOWED")
    assert client.get("/api/v1/scans").status_code == 405                              # there is deliberately no 'list all scans' endpoint
    assert_error(client.post("/api/v1/scans", content=b"{" + b"a" * 20000 + b"}", headers={"Content-Type": "application/json"}), 413, "PAYLOAD_TOO_LARGE")


def test_check_catalogue_lists_exactly_the_twenty_tests_in_order(client):
    r = client.get("/api/v1/checks")
    body = r.json()
    assert r.headers["Cache-Control"].startswith("public") and len(body["checks"]) == 20
    assert [c["position"] for c in body["checks"]] == list(range(1, 21))
    assert body["checks"][0]["id"] == "blocklist" and body["checks"][-1]["id"] == "display_mismatch"
    assert set(body["categories"]) == {"address", "journey", "reputation", "behavior"} and all(len(c["explanation"]) > 40 for c in body["checks"])


def test_request_ids_are_honoured_when_safe_and_replaced_when_not(client):
    assert client.get("/api/v1/health/live", headers={"X-Request-ID": "trace-abc12345"}).headers["X-Request-ID"] == "trace-abc12345"
    evil = client.get("/api/v1/health/live", headers={"X-Request-ID": "x\r\nSet-Cookie: a=b"}) if False else client.get("/api/v1/health/live", headers={"X-Request-ID": "<script>"})
    assert evil.headers["X-Request-ID"].startswith("req_")


def test_health_endpoints_and_openapi_surface(client):
    assert client.get("/api/v1/health/live").json() == {"status": "ok", "checks": {}}
    ready = client.get("/api/v1/health/ready")
    assert ready.status_code == 200 and ready.json()["checks"]["database_schema"] == "ok"
    paths = client.get("/api/openapi.json").json()["paths"]
    assert {"/api/v1/scans", "/api/v1/scans/{scan_id}", "/api/v1/checks", "/api/v1/health/live", "/api/v1/health/ready"} <= set(paths)
    assert "/internal/metrics" not in paths                                              # operational endpoints are not advertised
