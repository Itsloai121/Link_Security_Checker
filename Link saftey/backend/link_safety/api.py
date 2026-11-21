from __future__ import annotations

import asyncio
import json
import time
import uuid
from contextlib import asynccontextmanager
from pathlib import Path
from urllib.parse import urlsplit

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse
from starlette.middleware.trustedhost import TrustedHostMiddleware

from .config import Settings, load_settings
from .database import ScanRepository, make_report_credentials, new_scan_id, verify_report_token
from .errors import AppError
from .live_checks import run_live_checks
from .url_analysis import analyze_url


_STATIC = {"/": "index.html", "/index.html": "index.html", "/styles.css": "styles.css", "/app.js": "app.js"}
class FixedWindowRateLimiter:
    def __init__(self, window_ms: int, max_requests: int, max_entries: int = 5000):
        self.window_seconds = window_ms / 1000
        self.max_requests = max_requests
        self.max_entries = max_entries
        self.entries: dict[str, tuple[float, int]] = {}

    def consume(self, key: str, now: float | None = None) -> None:
        current = time.monotonic() if now is None else now
        entry = self.entries.get(key)
        if entry is None or current - entry[0] >= self.window_seconds:
            entry = (current, 0)
        if len(self.entries) >= self.max_entries and key not in self.entries:
            for candidate, value in list(self.entries.items()):
                if current - value[0] >= self.window_seconds:
                    self.entries.pop(candidate, None)
            if len(self.entries) >= self.max_entries:
                raise AppError(429, "RATE_LIMITED", "Too many requests. Try again shortly.")
        entry = (entry[0], entry[1] + 1)
        self.entries[key] = entry
        if entry[1] > self.max_requests:
            raise AppError(429, "RATE_LIMITED", "Too many requests. Try again shortly.")


def _write_log(environment: str, level: str, event: str, **fields) -> None:
    # Only caller-approved low-sensitivity values are accepted here; never pass URL/body/token/IP.
    if environment == "production":
        line = json.dumps({"timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "level": level,
                           "service": "link-safety-api", "environment": environment, "event": event, **fields}, separators=(",", ":"))
        print(line, flush=True)
    else:
        label = level.upper().ljust(5)
        context = "  ".join(f"{key}={value}" for key, value in fields.items())
        print(f"[{time.strftime('%H:%M:%S', time.gmtime())}Z] {label} {event.replace('_', ' ')}" + (f"  {context}" if context else ""), flush=True)


def create_app(settings: Settings | None = None) -> FastAPI:
    config = settings or load_settings()
    migration_directory = config.project_root / "migrations"
    public_directory = config.project_root / "public"
    repository = ScanRepository(config.database_path, migration_directory)
    limiter = FixedWindowRateLimiter(config.rate_limit_window_ms, config.rate_limit_max_requests)
    scan_semaphore = asyncio.Semaphore(config.max_concurrent_scans)

    @asynccontextmanager
    async def lifespan(_app: FastAPI):
        await asyncio.to_thread(repository.initialize)
        await asyncio.to_thread(repository.delete_expired, config.data_retention_days)
        stop = asyncio.Event()

        async def retention_loop() -> None:
            while not stop.is_set():
                try:
                    await asyncio.wait_for(stop.wait(), timeout=6 * 60 * 60)
                except asyncio.TimeoutError:
                    try:
                        await asyncio.to_thread(repository.delete_expired, config.data_retention_days)
                    except Exception as exc:  # Keep service alive; do not expose filesystem/database details.
                        _write_log(config.environment, "error", "retention_cleanup_failed", error_name=type(exc).__name__)

        cleanup = asyncio.create_task(retention_loop())
        _write_log(config.environment, "info", "server_started", bind_address=config.bind_address, port=config.port)
        try:
            yield
        finally:
            stop.set()
            cleanup.cancel()
            try:
                await cleanup
            except asyncio.CancelledError:
                pass
            await asyncio.to_thread(repository.close)
            _write_log(config.environment, "info", "server_stopped")

    app = FastAPI(title="Link Safety API", version="0.3.0", docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan)
    app.state.config = config
    app.state.repository = repository
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=list(config.allowed_hosts))

    @app.middleware("http")
    async def request_security(request: Request, call_next):
        request_id = str(uuid.uuid4())
        request.state.request_id = request_id
        started = time.perf_counter()
        path = request.url.path
        route = ("analyze_legacy" if path == "/api/analyze" else "create_scan" if path == "/api/v1/scans" else
                 "get_scan" if path.startswith("/api/v1/scans/") else "health" if path.startswith("/health/") else
                 "web_asset" if path in _STATIC else "other")
        try:
            if path.startswith(("/api/", "/health/")) and request.method in {"GET", "POST"}:
                client = request.client.host if request.client else "unknown"
                try:
                    limiter.consume(client)
                except AppError as exc:
                    response = _error_response(exc, request_id, path == "/api/analyze")
                    response.headers["X-Request-Id"] = request_id
                    return _secure_response(response, config)
            response = await call_next(request)
        except Exception as exc:
            _write_log(config.environment, "error", "request_failed", request_id=request_id, route=route, error_name=type(exc).__name__)
            response = _error_response(AppError(500, "INTERNAL_ERROR", "An unexpected server error occurred."), request_id, path == "/api/analyze")
        elapsed = round((time.perf_counter() - started) * 1000)
        response.headers["X-Request-Id"] = request_id
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
        response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
        response.headers["X-DNS-Prefetch-Control"] = "off"
        response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'"
        response.headers["Cache-Control"] = "no-store"
        if config.environment == "production":
            response.headers["Strict-Transport-Security"] = "max-age=31536000"
        if response.status_code >= 500:
            _write_log(config.environment, "warn", "http_request", request_id=request_id, route=route,
                       method=request.method, duration_ms=elapsed, status=response.status_code)
        else:
            _write_log(config.environment, "info", "http_request", request_id=request_id, route=route,
                       method=request.method, duration_ms=elapsed, status=response.status_code)
        return response

    @app.exception_handler(AppError)
    async def app_error_handler(request: Request, exc: AppError):
        response = _error_response(exc, getattr(request.state, "request_id", ""), request.url.path == "/api/analyze")
        if exc.status_code == 413:
            response.headers["Connection"] = "close"
        return response

    @app.get("/health/live")
    async def live(request: Request):
        return {"status": "ok", "request_id": request.state.request_id}

    @app.get("/health/ready")
    async def ready(request: Request):
        try:
            await asyncio.to_thread(repository.ping)
        except Exception as exc:
            _write_log(config.environment, "error", "readiness_check_failed", request_id=request.state.request_id, error_name=type(exc).__name__)
            raise AppError(503, "NOT_READY", "The service is not ready.") from exc
        return {"status": "ready", "request_id": request.state.request_id}

    @app.post("/api/analyze")
    async def analyze_legacy(request: Request):
        report = await _create_scan(request, config, repository, scan_semaphore)
        report.pop("input", None)
        report.pop("scan_id", None)
        report.pop("access_token", None)
        report.pop("created_at", None)
        report["request_id"] = request.state.request_id
        return JSONResponse(report, status_code=200)

    @app.post("/api/v1/scans")
    async def create_scan(request: Request):
        report = await _create_scan(request, config, repository, scan_semaphore)
        report.pop("input", None)
        report["request_id"] = request.state.request_id
        return JSONResponse(report, status_code=201)

    @app.get("/api/v1/scans/{scan_id}")
    async def get_scan(scan_id: str, request: Request):
        try:
            canonical_id = str(uuid.UUID(scan_id))
        except (ValueError, AttributeError) as exc:
            raise AppError(404, "NOT_FOUND", "The requested report was not found.") from exc
        authorization = request.headers.get("authorization", "")
        token = authorization[7:] if authorization.startswith("Bearer ") else None
        record = await asyncio.to_thread(repository.find_by_id, canonical_id)
        if record is None or not verify_report_token(record.get("access_token_hash", ""), token):
            raise AppError(404 if record is None else 401, "NOT_FOUND" if record is None else "UNAUTHORIZED",
                           "The requested report was not found." if record is None else "A valid report token is required.")
        record.pop("access_token_hash", None)
        record["checks"] = [{"id": item["id"], "title": item["title"], "description": item["description"],
                              "status": item["status"], "detail": item["detail"]} for item in record["checks"]]
        record["request_id"] = request.state.request_id
        return record

    @app.get("/", include_in_schema=False)
    @app.get("/index.html", include_in_schema=False)
    @app.get("/styles.css", include_in_schema=False)
    @app.get("/app.js", include_in_schema=False)
    async def static_file(request: Request):
        name = _STATIC.get(request.url.path)
        if not name:
            raise AppError(404, "NOT_FOUND", "The requested page was not found.")
        target = (public_directory / name).resolve()
        if target.parent != public_directory.resolve() or not target.is_file():
            raise AppError(404, "NOT_FOUND", "The requested page was not found.")
        media = {"index.html": "text/html; charset=utf-8", "styles.css": "text/css; charset=utf-8", "app.js": "text/javascript; charset=utf-8"}[name]
        return FileResponse(target, media_type=media)

    return app


async def _read_json(request: Request, max_bytes: int) -> dict:
    content_type = request.headers.get("content-type", "").split(";", 1)[0].strip().lower()
    if content_type != "application/json":
        raise AppError(415, "UNSUPPORTED_MEDIA_TYPE", "Content-Type must be application/json.")
    declared = request.headers.get("content-length")
    if declared:
        try:
            if int(declared) < 0:
                raise ValueError
            if int(declared) > max_bytes:
                raise AppError(413, "PAYLOAD_TOO_LARGE", "Request body is too large.")
        except ValueError as exc:
            raise AppError(400, "INVALID_REQUEST", "Content-Length is invalid.") from exc
    body = bytearray()
    async for chunk in request.stream():
        if len(body) + len(chunk) > max_bytes:
            raise AppError(413, "PAYLOAD_TOO_LARGE", "Request body is too large.")
        body.extend(chunk)
    try:
        def reject_duplicate_keys(pairs):
            result = {}
            for key, value in pairs:
                if key in result:
                    raise ValueError("Duplicate JSON object keys are not accepted.")
                result[key] = value
            return result

        def reject_constant(_value: str):
            raise ValueError("Invalid JSON constant.")

        parsed = json.loads(body, object_pairs_hook=reject_duplicate_keys, parse_constant=reject_constant)
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError, RecursionError) as exc:
        raise AppError(400, "INVALID_REQUEST", "Request body must contain valid JSON.") from exc
    if not isinstance(parsed, dict):
        raise AppError(400, "INVALID_REQUEST", "Request body must be a JSON object.")
    if set(parsed) != {"url"}:
        raise AppError(400, "INVALID_REQUEST", "Only the url field is accepted.")
    if not isinstance(parsed["url"], str):
        raise AppError(400, "INVALID_REQUEST", "The url field must be a string.")
    value = parsed["url"].strip()
    if not value:
        raise AppError(400, "INVALID_REQUEST", "Enter a URL to analyze.")
    return {"url": value}


async def _create_scan(request: Request, config: Settings, repository: ScanRepository, semaphore: asyncio.Semaphore) -> dict:
    body = await _read_json(request, config.max_body_bytes)
    try:
        analysis = analyze_url(body["url"], config.max_url_length)
    except ValueError as exc:
        raise AppError(400, "INVALID_REQUEST", str(exc)) from exc
    async with semaphore:
        analysis = await run_live_checks(analysis, phishtank_app_key=config.phishtank_app_key)
    token, token_hash = make_report_credentials()
    scan_id = new_scan_id()
    created_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    record = {
        "id": scan_id, "access_token_hash": token_hash, "host": analysis["host"],
        "scheme": urlsplit(analysis["normalized"]).scheme, "score": analysis["score"],
        "verdict": analysis["verdict"], "summary": analysis["summary"],
        "analyzer_version": "python-live-v1", "created_at": created_at, "checks": analysis["checks"],
    }
    try:
        await asyncio.to_thread(repository.create, record)
    except Exception as exc:
        _write_log(config.environment, "error", "scan_persistence_failed", request_id=request.state.request_id, error_name=type(exc).__name__)
        raise AppError(500, "INTERNAL_ERROR", "The scan report could not be saved.") from exc
    return {**analysis, "scan_id": scan_id, "access_token": token, "created_at": created_at}


def _error_response(error: AppError, request_id: str, legacy: bool) -> JSONResponse:
    message = "An unexpected server error occurred." if error.status_code >= 500 else error.message
    if legacy:
        return JSONResponse({"error": message, "request_id": request_id}, status_code=error.status_code)
    return JSONResponse({"error": {"code": error.code, "message": message, "request_id": request_id, "details": []}}, status_code=error.status_code)


def _secure_response(response, config: Settings):
    # Early rate-limit path does not pass through the normal middleware epilogue.
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
    response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
    response.headers["X-DNS-Prefetch-Control"] = "off"
    response.headers["Cache-Control"] = "no-store"
    response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'"
    if config.environment == "production":
        response.headers["Strict-Transport-Security"] = "max-age=31536000"
    return response
