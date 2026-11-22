from __future__ import annotations

import hmac

from fastapi import APIRouter, HTTPException, Request, Response
from fastapi.responses import JSONResponse, PlainTextResponse

from bootstrap.dependency_wiring import Container
from infrastructure.persistence.migrator import schema_is_current
from interfaces.api.schemas.scans import HealthOut

router = APIRouter(tags=["operations"])


@router.get("/api/v1/health/live", response_model=HealthOut, summary="Liveness: the process is running")
async def live() -> HealthOut:
    return HealthOut(status="ok")


@router.get("/api/v1/health/ready", response_model=HealthOut, summary="Readiness: database and schema are usable")
async def ready(request: Request) -> JSONResponse:
    c: Container = request.app.state.container
    try:
        ok, info = await __import__("asyncio").to_thread(schema_is_current, c.db, c.settings.migrations_dir)
    except Exception:  # pragma: no cover
        ok, info = False, "database unreachable"
    body = HealthOut(status="ok" if ok else "degraded", checks={"database_schema": "ok" if ok else info, "queue_depth": str(c.queue.depth)})
    return JSONResponse(body.model_dump(), status_code=200 if ok else 503)


@router.get("/internal/metrics", include_in_schema=False)
async def metrics(request: Request) -> Response:
    """Disabled (404) unless UNMASK_METRICS_TOKEN is set; compared in constant time."""
    c: Container = request.app.state.container
    secret = c.settings.metrics_token.get_secret_value() if c.settings.metrics_token else None
    supplied = request.headers.get("authorization", "").removeprefix("Bearer ").strip()
    if not secret or not hmac.compare_digest(supplied.encode(), secret.encode()):
        raise HTTPException(404)
    c.metrics.set_gauge("unmask_queue_depth", c.queue.depth)
    return PlainTextResponse(c.metrics.render(), media_type="text/plain; version=0.0.4")
