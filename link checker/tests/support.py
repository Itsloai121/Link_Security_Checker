"""Helpers shared by end-to-end, contract and security tests."""
import time


def run_scan(client, url, label=None, timeout=30):
    """Submit a link and poll until the scan finishes (as the web page does)."""
    r = client.post("/api/v1/scans", json={"url": url, "display_text": label})
    assert r.status_code == 202, r.text
    scan_id, deadline = r.json()["id"], time.time() + timeout
    while time.time() < deadline:
        body = client.get(f"/api/v1/scans/{scan_id}").json()
        if body["status"] in ("completed", "failed"):
            return body
        time.sleep(0.1)
    raise AssertionError("scan did not finish in time")


def check(scan, check_id):
    return next(c for c in scan["checks"] if c["id"] == check_id)
