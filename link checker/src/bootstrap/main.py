"""Application entry point: builds the FastAPI app, verifies the database, starts workers, and shuts down cleanly."""
from __future__ import annotations

import asyncio
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI

from bootstrap.dependency_wiring import Container, build_container
from bootstrap.settings import APP_VERSION, Settings
from infrastructure.observability.logging import configure_logging, event
from infrastructure.persistence.migrator import migrate, schema_is_current
from interfaces.api.middleware.body_limit import BodyLimitMiddleware
from interfaces.api.middleware.errors import install_error_handlers
from interfaces.api.middleware.request_context import RequestContextMiddleware
from interfaces.api.middleware.security_headers import SecurityHeadersMiddleware
from interfaces.api.routes import health, scans
from interfaces.web.serving import mount_web
from workers.handlers.run_scan_job import make_scan_handler
from workers.runner import WorkerPool
from workers.schedules.schedule import Scheduler, build_schedule

log = logging.getLogger("unmask.app")


def create_app(settings: Settings | None = None, container: Container | None = None) -> FastAPI:
    settings = settings or Settings()
    c = container or build_container(settings)

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        configure_logging(settings.log_level, environment=settings.environment, json_logs=settings.log_json)
        if settings.auto_migrate:
            applied = await asyncio.to_thread(migrate, c.db, settings.migrations_dir)
            if applied:
                event(log, "migrations_applied", migrations=",".join(applied))
        ok, info = await asyncio.to_thread(schema_is_current, c.db, settings.migrations_dir)
        if not ok:  # fail fast: the app never alters the schema by itself (USSA pillar 5)
            raise RuntimeError(f"Database is not ready ({info}). Run: python -m interfaces.cli migrate")
        await c.recover_scans.execute()
        pool = WorkerPool(c.queue, make_scan_handler(c), settings.worker_concurrency, c.metrics)
        await pool.start()
        scheduler = Scheduler(build_schedule(c))
        scheduler.start()
        event(log, "app_started", version=APP_VERSION, environment=settings.environment, workers=settings.worker_concurrency)
        try:
            yield
        finally:
            await scheduler.stop()
            await pool.stop()
            await c.aclose()
            event(log, "app_stopped")

    dev = settings.is_dev
    app = FastAPI(title="Unmask Link Security API", version=APP_VERSION, lifespan=lifespan, docs_url="/api/docs" if dev else None,
                  redoc_url=None, openapi_url="/api/openapi.json" if dev else None)
    app.state.container = c
    # Order matters: the LAST added is the OUTERMOST. Security headers wrap everything, including error responses.
    app.add_middleware(BodyLimitMiddleware, max_bytes=settings.max_body_bytes)
    app.add_middleware(RequestContextMiddleware, metrics=c.metrics)
    app.add_middleware(SecurityHeadersMiddleware, hsts=settings.hsts)
    install_error_handlers(app)
    app.include_router(scans.router)
    app.include_router(health.router)
    mount_web(app, settings.web_dir, settings.assets_dir, max_age=0 if dev else 3600)
    return app


def main() -> None:  # python -m bootstrap.main
    from interfaces.cli.commands import main as cli_main
    cli_main(["serve"])


if __name__ == "__main__":
    main()
