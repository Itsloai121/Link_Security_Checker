"""Reject oversized request bodies early (USSA pillar 3/4): both declared (Content-Length) and streamed (chunked)."""
from __future__ import annotations

import json

from shared.utilities.ids import REQUEST_ID_RE  # noqa: F401  (kept for symmetry with the other middleware)


class _TooLarge(Exception):
    pass


class BodyLimitMiddleware:
    def __init__(self, app, max_bytes: int):
        self.app, self.max_bytes = app, max_bytes

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or scope["method"] in ("GET", "HEAD", "OPTIONS"):
            return await self.app(scope, receive, send)
        declared = next((v for k, v in scope["headers"] if k == b"content-length"), b"")
        if declared.isdigit() and int(declared) > self.max_bytes:
            return await self._reject(send)
        seen, started = 0, False

        async def limited_receive():
            nonlocal seen
            msg = await receive()
            if msg["type"] == "http.request":
                seen += len(msg.get("body", b""))
                if seen > self.max_bytes:
                    raise _TooLarge()
            return msg

        async def tracking_send(message):
            nonlocal started
            started = started or message["type"] == "http.response.start"
            await send(message)

        try:
            await self.app(scope, limited_receive, tracking_send)
        except _TooLarge:
            if not started:
                await self._reject(send)

    async def _reject(self, send) -> None:
        from infrastructure.observability.logging import request_id_var
        body = json.dumps({"error": {"code": "PAYLOAD_TOO_LARGE", "message": "The request is too large.", "request_id": request_id_var.get(), "details": []}}).encode()
        await send({"type": "http.response.start", "status": 413, "headers": [(b"content-type", b"application/json"), (b"content-length", str(len(body)).encode()), (b"connection", b"close")]})
        await send({"type": "http.response.body", "body": body})
