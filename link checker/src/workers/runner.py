"""Background worker pool: pulls scan IDs off the in-process queue and runs the analysis (USBA §9)."""
from __future__ import annotations

import asyncio
import logging
from collections.abc import Awaitable, Callable

from infrastructure.messaging.in_process_queue import InProcessJobQueue
from infrastructure.observability.logging import event
from infrastructure.observability.metrics import Metrics

log = logging.getLogger("unmask.workers")


class WorkerPool:
    def __init__(self, queue: InProcessJobQueue, handler: Callable[[str], Awaitable[None]], concurrency: int, metrics: Metrics):
        self.queue, self.handler, self.concurrency, self.metrics = queue, handler, concurrency, metrics
        self._tasks: list[asyncio.Task] = []

    async def start(self) -> None:
        self._tasks = [asyncio.create_task(self._loop(i), name=f"scan-worker-{i}") for i in range(self.concurrency)]

    async def _loop(self, index: int) -> None:
        while True:
            job = await self.queue.get()
            try:
                await self.handler(job)
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # the handler already records failures; this is the last line of defence
                self.metrics.inc("unmask_worker_errors_total")
                event(log, "worker_job_crashed", logging.ERROR, worker=index, exc_type=type(exc).__name__)
            finally:
                self.queue.task_done()
                self.metrics.set_gauge("unmask_queue_depth", self.queue.depth)

    async def stop(self) -> None:
        for t in self._tasks:
            t.cancel()
        await asyncio.gather(*self._tasks, return_exceptions=True)
        self._tasks = []
