"""Non-persistent ScanRepository: used by the CLI `scan` command (nothing is stored) and by unit tests."""
from __future__ import annotations

import copy
from datetime import datetime

from modules.link_analysis.domain.checks.base import CheckResult
from modules.link_analysis.domain.scan import Scan, ScanStatus


class InMemoryScanRepository:
    def __init__(self) -> None:
        self._scans: dict[str, Scan] = {}

    async def add(self, scan: Scan) -> None:
        self._scans[scan.id] = copy.deepcopy(scan)

    async def get(self, scan_id: str) -> Scan | None:
        s = self._scans.get(scan_id)
        return copy.deepcopy(s) if s else None

    async def save(self, scan: Scan) -> None:
        stored = self._scans.get(scan.id)
        if stored is not None:
            results = stored.results
            self._scans[scan.id] = copy.deepcopy(scan)
            self._scans[scan.id].results = results

    async def save_result(self, scan_id: str, result: CheckResult) -> None:
        s = self._scans.get(scan_id)
        if s is not None:
            s.results = [r for r in s.results if r.check_id != result.check_id] + [result]

    async def delete(self, scan_id: str) -> bool:
        return self._scans.pop(scan_id, None) is not None

    async def purge_expired(self, now: datetime) -> int:
        gone = [k for k, s in self._scans.items() if s.expires_at <= now]
        for k in gone:
            del self._scans[k]
        return len(gone)

    async def ids_with_status(self, status: ScanStatus, limit: int = 500) -> list[str]:
        return [k for k, s in self._scans.items() if s.status is status][:limit]

    async def fail_stale_running(self, before: datetime, now: datetime) -> int:
        n = 0
        for s in self._scans.values():
            if s.status is ScanStatus.RUNNING and s.started_at and s.started_at <= before:
                s.fail(now, "INTERRUPTED"); n += 1
        return n
