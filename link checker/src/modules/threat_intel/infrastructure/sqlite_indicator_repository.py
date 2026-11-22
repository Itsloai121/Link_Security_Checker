from __future__ import annotations

import sqlite3
from datetime import datetime
from collections.abc import Sequence

from infrastructure.persistence.sqlite import SqliteDatabase
from modules.threat_intel.domain.indicators import Indicator, IndicatorHit
from shared.utilities.time import to_iso

_CHUNK = 500


class SqliteIndicatorRepository:
    """Sole owner of the threat_indicators and feed_updates tables."""

    def __init__(self, db: SqliteDatabase):
        self.db = db

    async def replace_source(self, source: str, indicators: Sequence[Indicator], now: datetime) -> int:
        stamp = to_iso(now)

        def _do(conn: sqlite3.Connection) -> int:
            prev = conn.execute("SELECT COUNT(*) FROM threat_indicators WHERE source = ?", (source,)).fetchone()[0]
            conn.execute("DELETE FROM threat_indicators WHERE source = ?", (source,))
            conn.executemany("INSERT OR IGNORE INTO threat_indicators (source, kind, value, category, loaded_at) VALUES (?,?,?,?,?)",
                             ((source, i.kind, i.value, i.category, stamp) for i in indicators))
            return prev
        return await self.db.run(_do)  # one transaction: readers see the old set or the new set, never a mix

    async def count(self, source: str) -> int:
        return await self.db.run(lambda c: c.execute("SELECT COUNT(*) FROM threat_indicators WHERE source = ?", (source,)).fetchone()[0], write=False)

    async def find(self, kind: str, values: Sequence[str]) -> list[IndicatorHit]:
        def _do(conn: sqlite3.Connection) -> list[IndicatorHit]:
            out: list[IndicatorHit] = []
            for i in range(0, len(values), _CHUNK):
                chunk = list(values[i:i + _CHUNK])
                marks = ",".join("?" * len(chunk))
                rows = conn.execute(f"SELECT source, kind, value, category, loaded_at FROM threat_indicators WHERE kind = ? AND value IN ({marks})", [kind, *chunk])
                out += [IndicatorHit(r["source"], r["kind"], r["value"], r["category"], r["loaded_at"]) for r in rows]
            return out
        return await self.db.run(_do, write=False)

    async def all_of_kind(self, kind: str) -> list[IndicatorHit]:
        return await self.db.run(lambda c: [IndicatorHit(r["source"], r["kind"], r["value"], r["category"], r["loaded_at"])
                                            for r in c.execute("SELECT source, kind, value, category, loaded_at FROM threat_indicators WHERE kind = ?", (kind,))], write=False)

    async def start_update(self, source: str, now: datetime) -> int:
        return await self.db.run(lambda c: c.execute("INSERT INTO feed_updates (source, started_at, status) VALUES (?,?, 'running')", (source, to_iso(now))).lastrowid)

    async def finish_update(self, update_id: int, *, status: str, loaded: int | None, previous: int | None, note: str | None, now: datetime) -> None:
        await self.db.run(lambda c: c.execute("UPDATE feed_updates SET status=?, indicators_loaded=?, previous_count=?, note=?, finished_at=? WHERE id=?",
                                              (status if status in ("succeeded", "rejected", "failed") else "failed", loaded, previous, note, to_iso(now), update_id)))

    async def last_updates(self) -> dict[str, dict]:
        def _do(conn: sqlite3.Connection) -> dict[str, dict]:
            rows = conn.execute("SELECT source, status, finished_at, note FROM feed_updates WHERE id IN (SELECT MAX(id) FROM feed_updates GROUP BY source)")
            return {r["source"]: dict(r) for r in rows}
        return await self.db.run(_do, write=False)

    async def freshness(self) -> dict[str, str]:
        return await self.db.run(lambda c: {r["source"]: r["t"] for r in c.execute("SELECT source, MAX(loaded_at) AS t FROM threat_indicators GROUP BY source")}, write=False)
