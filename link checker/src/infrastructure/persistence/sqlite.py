"""SQLite access (USDA §6: one well-designed transactional store; USBA §8: persistence behind adapters).

A short-lived connection per unit of work keeps transactions small and thread-safe. WAL mode allows
concurrent readers while one writer commits. All SQL uses bound parameters (USSA pillar 3/5).
"""
from __future__ import annotations

import asyncio
import os
import sqlite3
from pathlib import Path
from typing import TypeVar
from collections.abc import Callable

T = TypeVar("T")


class SqliteDatabase:
    def __init__(self, path: str | Path, *, busy_timeout_ms: int = 5000):
        self.path = str(path)
        self._busy = busy_timeout_ms
        if self.path != ":memory:":
            parent = Path(self.path).resolve().parent
            parent.mkdir(parents=True, exist_ok=True)
            try:
                os.chmod(parent, 0o700)  # data store is private by default (USSA pillar 5); no-op on Windows
            except OSError:  # pragma: no cover
                pass

    def connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path, timeout=self._busy / 1000, isolation_level=None, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        conn.execute("PRAGMA trusted_schema = OFF")
        conn.execute(f"PRAGMA busy_timeout = {int(self._busy)}")
        if self.path != ":memory:":
            conn.execute("PRAGMA journal_mode = WAL")
            conn.execute("PRAGMA synchronous = NORMAL")
        return conn

    def run_sync(self, fn: Callable[[sqlite3.Connection], T], *, write: bool = True) -> T:
        conn = self.connect()
        try:
            conn.execute("BEGIN IMMEDIATE" if write else "BEGIN")
            try:
                result = fn(conn)
                conn.execute("COMMIT")
                return result
            except BaseException:
                conn.execute("ROLLBACK")
                raise
        finally:
            conn.close()

    async def run(self, fn: Callable[[sqlite3.Connection], T], *, write: bool = True) -> T:
        return await asyncio.to_thread(self.run_sync, fn, write=write)
