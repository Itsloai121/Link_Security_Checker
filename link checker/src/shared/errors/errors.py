"""Typed application errors (USBA §13).

The domain and application layers raise these; only the interface layer maps
them to a transport (HTTP status, CLI exit code). Nothing here knows about HTTP.
"""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(eq=False)
class AppError(Exception):
    """Base class. `code` is a stable, documented identifier callers may act on."""

    message: str = "Unexpected error."
    details: list[dict[str, str]] = field(default_factory=list)
    code: str = "INTERNAL_ERROR"

    def __str__(self) -> str:  # pragma: no cover - trivial
        return f"{self.code}: {self.message}"


class ValidationFailed(AppError):
    def __init__(self, message: str = "The request is not valid.", details: list[dict[str, str]] | None = None):
        super().__init__(message, details or [], "VALIDATION_FAILED")


class NotFound(AppError):
    def __init__(self, message: str = "The requested resource was not found.", code: str = "NOT_FOUND"):
        super().__init__(message, [], code)


class Conflict(AppError):
    def __init__(self, message: str = "The request conflicts with the current state."):
        super().__init__(message, [], "CONFLICT")


class BusinessRuleViolation(AppError):
    def __init__(self, message: str, code: str = "BUSINESS_RULE_VIOLATION"):
        super().__init__(message, [], code)


class DependencyFailure(AppError):
    """An external dependency (DNS, registry, feed, database) failed."""

    def __init__(self, message: str = "A required dependency is unavailable.", code: str = "DEPENDENCY_FAILURE"):
        super().__init__(message, [], code)


class OperationTimeout(AppError):
    def __init__(self, message: str = "The operation took too long."):
        super().__init__(message, [], "TIMEOUT")


class RateLimited(AppError):
    def __init__(self, retry_after_seconds: int, message: str = "Too many requests. Please slow down."):
        super().__init__(message, [], "RATE_LIMITED")
        self.retry_after_seconds = retry_after_seconds


class ServiceBusy(AppError):
    def __init__(self, message: str = "The service is busy. Try again in a moment.", retry_after_seconds: int = 10):
        super().__init__(message, [], "SERVICE_BUSY")
        self.retry_after_seconds = retry_after_seconds


class InternalFailure(AppError):
    def __init__(self, message: str = "Something went wrong on our side."):
        super().__init__(message, [], "INTERNAL_ERROR")
