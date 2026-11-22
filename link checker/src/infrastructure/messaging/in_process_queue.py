"""Bounded in-process job queue (USBA §9: a message broker is not justified for a single-node app).

Jobs are scan IDs only. The durable record is the `scans` row, so a crash never loses work: on startup,
queued rows are re-enqueued and abandoned 'running' rows are failed (see workers/runner.py).
"""
from __future__ import annotations

import asyncio


class QueueFull(Exception):
    pass


class InProcessJobQueue:
    def __init__(self, maxsize: int = 200):
        self._q: asyncio.Queue[str] = asyncio.Queue(maxsize=maxsize)

    def enqueue_nowait(self, job_id: str) -> None:
        try:
            self._q.put_nowait(job_id)
        except asyncio.QueueFull as exc:
            raise QueueFull() from exc

    async def enqueue(self, job_id: str) -> None:
        self.enqueue_nowait(job_id)

    async def get(self) -> str:
        return await self._q.get()

    def task_done(self) -> None:
        self._q.task_done()

    @property
    def depth(self) -> int:
        return self._q.qsize()
