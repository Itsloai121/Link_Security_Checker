from dataclasses import dataclass


@dataclass(slots=True)
class AppError(Exception):
    status_code: int
    code: str
    message: str

    def __str__(self) -> str:
        return self.message


class InspectionError(Exception):
    """An expected failure while checking a submitted or provider URL."""


class PolicyBlocked(InspectionError):
    """A URL or resolved address was rejected by the outbound safety policy."""
