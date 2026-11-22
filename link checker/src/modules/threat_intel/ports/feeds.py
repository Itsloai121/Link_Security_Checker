from __future__ import annotations

from datetime import datetime
from typing import Protocol
from collections.abc import Sequence

from modules.threat_intel.domain.indicators import FeedDefinition, Indicator, IndicatorHit


class IndicatorRepository(Protocol):
    async def replace_source(self, source: str, indicators: Sequence[Indicator], now: datetime) -> int:
        """Atomically replace every indicator of one source. Returns the previous count."""

    async def count(self, source: str) -> int: ...
    async def find(self, kind: str, values: Sequence[str]) -> list[IndicatorHit]: ...
    async def all_of_kind(self, kind: str) -> list[IndicatorHit]: ...
    async def start_update(self, source: str, now: datetime) -> int: ...
    async def finish_update(self, update_id: int, *, status: str, loaded: int | None, previous: int | None, note: str | None, now: datetime) -> None: ...
    async def last_updates(self) -> dict[str, dict]: ...
    async def freshness(self) -> dict[str, str]: ...


class FeedDownloader(Protocol):
    async def download(self, feed: FeedDefinition) -> str:
        """Return the feed body as text. Raise `DependencyFailure` on any failure."""


class FeedCatalog(Protocol):
    def feeds(self) -> list[FeedDefinition]: ...
