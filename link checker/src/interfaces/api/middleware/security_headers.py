"""Browser-side defences (USSA pillar 08): strict CSP, no framing, no sniffing, no referrer leakage, no caching of reports."""
from __future__ import annotations

from starlette.datastructures import MutableHeaders

CSP = ("default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; "
       "base-uri 'none'; form-action 'self'; frame-ancestors 'none'; object-src 'none'")
BASE = {
    "Content-Security-Policy": CSP,
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=(), payment=(), interest-cohort=()",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
}


class SecurityHeadersMiddleware:
    def __init__(self, app, hsts: bool = False):
        self.app, self.hsts = app, hsts

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        path = scope.get("path", "")

        async def send_wrapper(message):
            if message["type"] == "http.response.start":
                h = MutableHeaders(scope=message)
                for k, v in BASE.items():
                    h[k] = v
                if self.hsts:
                    h["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
                if (path.startswith("/api/") or path.startswith("/internal/")) and "cache-control" not in h:
                    h["Cache-Control"] = "no-store"  # default for API data; a route may choose otherwise (e.g. the static check catalogue)
                if "server" in h:
                    del h["server"]
            await send(message)

        await self.app(scope, receive, send_wrapper)
