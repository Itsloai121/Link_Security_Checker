from __future__ import annotations

from typing import Protocol


class ScanJobQueue(Protocol):
    def enqueue_nowait(self, scan_id: str) -> None:
        """Raise `QueueFull` (infrastructure.messaging) when the queue is at capacity."""
