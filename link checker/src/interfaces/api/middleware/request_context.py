"""Request ID, access log, metrics, and a last-resort 500 that still carries the request ID (pure ASGI, no body buffering)."""
from __future__ import annotations

import json
import logging
import time

from starlette.datastructures import MutableHeaders

from infrastructure.observability.logging import event, request_id_var
from infrastructure.observability.metrics import Metrics
from shared.utilities.ids import REQUEST_ID_RE, SecureIdGenerator

log = logging.getLogger("unmask.access")


class RequestContextMiddleware:
    def __init__(self, app, metrics: Metrics, ids: SecureIdGenerator | None = None):
        self.app, self.metrics, self.ids = app, metrics, ids or SecureIdGenerator()

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        inbound = next((v.decode("latin-1") for k, v in scope["headers"] if k == b"x-request-id"), "")
        rid = inbound if REQUEST_ID_RE.fullmatch(inbound) else self.ids.new_request_id()
        token = request_id_var.set(rid)
        started, status, response_started = time.monotonic(), 500, False

        async def send_wrapper(message):
            nonlocal status, response_started
            if message["type"] == "http.response.start":
                status, response_started = message["status"], True
                MutableHeaders(scope=message)["X-Request-ID"] = rid
            await send(message)

        try:
            await self.app(scope, receive, send_wrapper)
        except Exception as exc:  # anything the framework did not handle
            event(log, "unhandled_exception", logging.ERROR, exc_type=type(exc).__name__)
            if not response_started:
                body = json.dumps({"error": {"code": "INTERNAL_ERROR", "message": "Something went wrong on our side.", "request_id": rid, "details": []}}).encode()
                await send_wrapper({"type": "http.response.start", "status": 500, "headers": [(b"content-type", b"application/json"), (b"content-length", str(len(body)).encode())]})
                await send_wrapper({"type": "http.response.body", "body": body})
        finally:
            route = getattr(scope.get("route"), "path", None)
            path = scope.get("path", "")
            template = route or ("static" if path.startswith(("/static/", "/assets/")) else "unmatched")
            elapsed = time.monotonic() - started
            self.metrics.inc("unmask_http_requests_total", {"method": scope["method"], "route": template, "status": str(status)})
            self.metrics.observe("unmask_http_request_duration_seconds", elapsed, {"route": template})
            if not path.startswith(("/static/", "/assets/")):
                event(log, "http_request", method=scope["method"], route=template, status=status, duration_ms=int(elapsed * 1000))  # no query string, no client address
            request_id_var.reset(token)
