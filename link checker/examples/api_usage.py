"""Submit a link to a running Unmask server and print the report. Standard library only.

    python examples/api_usage.py "https://secure.paypal.com@login-paypa1.example/signin" --label "paypal.com/signin"
"""
import argparse
import json
import time
import urllib.request

parser = argparse.ArgumentParser()
parser.add_argument("url")
parser.add_argument("--label", help="the visible link text, for the label/destination test")
parser.add_argument("--server", default="http://127.0.0.1:8000")
args = parser.parse_args()
if not args.server.startswith(("http://", "https://")):
    parser.error("--server must start with http:// or https://")


def call(method, path, body=None):
    data = json.dumps(body).encode() if body else None
    request = urllib.request.Request(args.server + path, method=method, data=data, headers={"Content-Type": "application/json"})  # noqa: S310
    with urllib.request.urlopen(request, timeout=30) as response:  # noqa: S310 (scheme validated above)
        return json.loads(response.read() or "null")


scan = call("POST", "/api/v1/scans", {"url": args.url, "display_text": args.label})
while scan["status"] not in ("completed", "failed"):
    time.sleep(1)
    scan = call("GET", f"/api/v1/scans/{scan['id']}")
    print(f"  {scan['progress']['done']}/{scan['progress']['total']} tests done", end="\r")
print(f"\n{scan['headline']}  (risk {scan['risk_score']}/100, {scan['coverage_percent']}% of tests could verify)")
for reason in scan["reasons"]:
    print(" -", reason)
for check in scan["checks"]:
    print(f"{check['position']:>3}. [{check['status']:<11}] {check['title']}: {check['summary']}")
call("DELETE", f"/api/v1/scans/{scan['id']}")   # good manners: delete the report when you are done
