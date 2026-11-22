"""Structured JSON logs with request correlation (USBA §15, USSA pillar 11). Never log secrets or full URLs."""
from __future__ import annotations

import contextvars
import json
import logging
import sys
from datetime import datetime, timezone

request_id_var: contextvars.ContextVar[str] = contextvars.ContextVar("request_id", default="-")
scan_id_var: contextvars.ContextVar[str] = contextvars.ContextVar("scan_id", default="-")

_RESERVED = set(logging.LogRecord("", 0, "", 0, "", (), None).__dict__) | {"message", "asctime"}
_SENSITIVE_KEYS = {"password", "token", "authorization", "api_key", "secret", "cookie"}


class JsonFormatter(logging.Formatter):
    def __init__(self, service: str, environment: str):
        super().__init__()
        self.service, self.environment = service, environment

    def format(self, record: logging.LogRecord) -> str:
        payload = {
            "ts": datetime.fromtimestamp(record.created, timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z",
            "level": record.levelname, "service": self.service, "env": self.environment,
            "logger": record.name, "event": record.getMessage(),
            "request_id": request_id_var.get(), "scan_id": scan_id_var.get(),
        }
        for key, value in record.__dict__.items():
            if key in _RESERVED or key.startswith("_"):
                continue
            payload[key] = "[redacted]" if key.lower() in _SENSITIVE_KEYS else value
        if record.exc_info:
            payload["exc_type"] = record.exc_info[0].__name__ if record.exc_info[0] else None  # no stack trace to users; type only
            payload["exc"] = self.formatException(record.exc_info)
        return json.dumps(payload, default=str, ensure_ascii=False)


def configure_logging(level: str = "INFO", *, service: str = "unmask", environment: str = "development", json_logs: bool = True) -> None:
    root = logging.getLogger()
    for h in list(root.handlers):
        root.removeHandler(h)
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter(service, environment) if json_logs else logging.Formatter("%(levelname)s %(name)s: %(message)s"))
    root.addHandler(handler)
    root.setLevel(level.upper())
    logging.getLogger("uvicorn.access").disabled = True  # we emit our own access log without query strings


def event(logger: logging.Logger, name: str, level: int = logging.INFO, **fields) -> None:
    logger.log(level, name, extra=fields)


security_log = logging.getLogger("unmask.security")
