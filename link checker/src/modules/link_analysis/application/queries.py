"""Read-side and housekeeping use cases."""
from __future__ import annotations

import logging
from datetime import timedelta

from infrastructure.messaging.in_process_queue import QueueFull
from infrastructure.observability.logging import event
from modules.link_analysis.application.settings import AnalysisPolicy
from modules.link_analysis.domain.checks.base import CheckSpec
from modules.link_analysis.domain.checks.catalog import specs
from modules.link_analysis.domain.scan import Scan, ScanStatus
from modules.link_analysis.ports.job_queue import ScanJobQueue
from modules.link_analysis.ports.scan_repository import ScanRepository
from shared.contracts.clock import Clock
from shared.errors import NotFound
from shared.utilities.ids import is_valid_scan_id

log = logging.getLogger("unmask.housekeeping")


class GetScanResult:
    def __init__(self, repo: ScanRepository, clock: Clock):
        self.repo, self.clock = repo, clock

    async def execute(self, scan_id: str) -> Scan:
        if not is_valid_scan_id(scan_id):
            raise NotFound("This report does not exist or has expired.", "SCAN_NOT_FOUND")
        scan = await self.repo.get(scan_id)
        if scan is None or scan.expires_at <= self.clock.now():
            raise NotFound("This report does not exist or has expired.", "SCAN_NOT_FOUND")
        return scan


class DeleteScan:
    def __init__(self, repo: ScanRepository):
        self.repo = repo

    async def execute(self, scan_id: str) -> None:
        if not is_valid_scan_id(scan_id) or not await self.repo.delete(scan_id):
            raise NotFound("This report does not exist or has expired.", "SCAN_NOT_FOUND")


class ListCheckCatalog:
    def execute(self) -> tuple[CheckSpec, ...]:
        return specs()


class PurgeExpiredScans:
    """Retention (USDA §14): expired reports are deleted, not archived."""

    def __init__(self, repo: ScanRepository, clock: Clock):
        self.repo, self.clock = repo, clock

    async def execute(self) -> int:
        n = await self.repo.purge_expired(self.clock.now())
        if n:
            event(log, "scans_purged", count=n)
        return n


class RecoverInterruptedScans:
    """On startup: re-enqueue scans that never started; fail scans a crashed process left 'running' (USBA §9 recovery)."""

    def __init__(self, repo: ScanRepository, queue: ScanJobQueue, clock: Clock, policy: AnalysisPolicy):
        self.repo, self.queue, self.clock, self.policy = repo, queue, clock, policy

    async def execute(self) -> tuple[int, int]:
        now = self.clock.now()
        failed = await self.repo.fail_stale_running(now - timedelta(seconds=1), now)
        requeued = 0
        for scan_id in await self.repo.ids_with_status(ScanStatus.QUEUED):
            try:
                self.queue.enqueue_nowait(scan_id)
                requeued += 1
            except QueueFull:
                break
        if requeued or failed:
            event(log, "scans_recovered", requeued=requeued, failed=failed)
        return requeued, failed
