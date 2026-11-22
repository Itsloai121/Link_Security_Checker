"""Demo mode: run the real app against a local fixture 'internet' so you can explore the GUI offline.

    python scripts/demo_server.py          # then open http://127.0.0.1:8765

DNS, domain-age, TLS and blocklist answers are SIMULATED; only the fixture pages on this machine are really fetched.
"""
from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "src"), str(ROOT)]

import uvicorn  # noqa: E402

from bootstrap.main import create_app  # noqa: E402
from infrastructure.persistence.migrator import migrate  # noqa: E402
from tests.fixtures.fakes import build_test_container  # noqa: E402
from tests.fixtures.fixture_site import FixtureSite  # noqa: E402


def main() -> None:
    site = FixtureSite(int(os.environ.get("UNMASK_DEMO_FIXTURE_PORT", "8766"))).start()  # fixed port: the demo links below stay the same every run
    tmp = Path(tempfile.mkdtemp(prefix="unmask-demo-"))
    container = build_test_container(tmp, site, environment="development", rate_limit_submit_per_minute=200, per_host_scans_per_minute=100)
    migrate(container.db, container.settings.migrations_dir)
    app = create_app(container.settings, container)
    print("\n  UNMASK DEMO MODE: network answers are simulated. Try these links on the Check page:\n")
    for label, host, path in [("phishing page (new domain, blocklisted, cloaked form)", "login-paypa1.test", "/signin"), ("short link -> redirect chain", "short.test", "/abc"),
                              ("trusted site with an open redirect", "www.paypal.com", f"/go?url=http://login-paypa1.test:{site.port}/signin"),
                              ("'invoice.pdf' that is really a program", "dl.test", "/invoice.pdf"), ("page that hides from scanners", "cloak.test", "/"),
                              ("an ordinary page", "news.test", "/")]:
        print(f"    {label:<55} {site.url(host, path)}")
    print("\n  Open http://127.0.0.1:8765\n")
    try:
        uvicorn.run(app, host="127.0.0.1", port=8765, log_level="warning")
    finally:
        site.stop()


if __name__ == "__main__":
    main()
