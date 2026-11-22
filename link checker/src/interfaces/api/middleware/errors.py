"""One error contract for every failure (USBA §13): {"error": {"code", "message", "request_id", "details": []}}."""
from __future__ import annotations

import logging

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from infrastructure.observability.logging import event, request_id_var
from shared.errors import AppError, RateLimited, ServiceBusy

log = logging.getLogger("unmask.api")
STATUS = {"VALIDATION_FAILED": 422, "NOT_FOUND": 404, "SCAN_NOT_FOUND": 404, "CONFLICT": 409, "BUSINESS_RULE_VIOLATION": 409, "RATE_LIMITED": 429,
          "SERVICE_BUSY": 503, "TIMEOUT": 504, "DEPENDENCY_FAILURE": 502, "INTERNAL_ERROR": 500}


def error_payload(code: str, message: str, details: list[dict] | None = None) -> dict:
    return {"error": {"code": code, "message": message, "request_id": request_id_var.get(), "details": details or []}}


def install_error_handlers(app: FastAPI) -> None:
    @app.exception_handler(AppError)
    async def _app_error(_: Request, exc: AppError) -> JSONResponse:
        headers = {}
        if isinstance(exc, (RateLimited, ServiceBusy)):
            headers["Retry-After"] = str(exc.retry_after_seconds)
        return JSONResponse(error_payload(exc.code, exc.message, exc.details), status_code=STATUS.get(exc.code, 500), headers=headers)

    @app.exception_handler(RequestValidationError)
    async def _validation(_: Request, exc: RequestValidationError) -> JSONResponse:
        # Only field path + message: never echo the submitted value back.
        details = [{"field": ".".join(str(p) for p in e.get("loc", []) if p != "body") or None, "issue": str(e.get("msg", "invalid"))[:200]} for e in exc.errors()[:10]]
        return JSONResponse(error_payload("VALIDATION_FAILED", "The request is not valid.", details), status_code=422)

    @app.exception_handler(StarletteHTTPException)
    async def _http(_: Request, exc: StarletteHTTPException) -> JSONResponse:
        code = {404: "NOT_FOUND", 405: "METHOD_NOT_ALLOWED", 413: "PAYLOAD_TOO_LARGE", 415: "UNSUPPORTED_MEDIA_TYPE"}.get(exc.status_code, "HTTP_ERROR")
        msg = {404: "That address does not exist.", 405: "That method is not allowed here."}.get(exc.status_code, "The request could not be processed.")
        return JSONResponse(error_payload(code, msg), status_code=exc.status_code, headers=getattr(exc, "headers", None))

    @app.exception_handler(Exception)
    async def _unexpected(_: Request, exc: Exception) -> JSONResponse:
        event(log, "unhandled_exception", logging.ERROR, exc_type=type(exc).__name__)
        return JSONResponse(error_payload("INTERNAL_ERROR", "Something went wrong on our side."), status_code=500)
