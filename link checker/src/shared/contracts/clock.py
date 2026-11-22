"""Small shared contracts. Anything time- or randomness-dependent is injected so tests stay deterministic."""
from __future__ import annotations

from datetime import datetime
from typing import Protocol


class Clock(Protocol):
    def now(self) -> datetime:
        """Return the current time as a timezone-aware UTC datetime."""


class IdGenerator(Protocol):
    def new_scan_id(self) -> str: ...

    def new_request_id(self) -> str: ...
