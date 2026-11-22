"""Recurring tasks, defined declaratively and run by a tiny in-process scheduler (no cron daemon needed)."""
from __future__ import annotations

import asyncio
import logging
import random
from dataclasses import dataclass
from collections.abc import Awaitable, Callable

from bootstrap.dependency_wiring import Container
from infrastructure.observability.logging import event
from workers.handlers.maintenance import purge_expired_scans, refresh_threat_feeds

log = logging.getLogger("unmask.scheduler")


@dataclass(frozen=True)
class ScheduledJob:
    name: str
    interval_seconds: float
    run: Callable[[], Awaitable[object]]
    run_on_start: bool = False


def build_schedule(c: Container) -> list[ScheduledJob]:
    jobs = [ScheduledJob("purge_expired_scans", c.settings.purge_interval_minutes * 60, lambda: purge_expired_scans(c), run_on_start=True)]
    if c.settings.feed_refresh_hours > 0:
        jobs.append(ScheduledJob("refresh_threat_feeds", c.settings.feed_refresh_hours * 3600, lambda: refresh_threat_feeds(c), run_on_start=True))
    return jobs


class Scheduler:
    def __init__(self, jobs: list[ScheduledJob]):
        self.jobs, self._tasks = jobs, []

    def start(self) -> None:
        self._tasks = [asyncio.create_task(self._loop(j), name=f"schedule-{j.name}") for j in self.jobs]

    async def _loop(self, job: ScheduledJob) -> None:
        first = True
        while True:
            if not (first and job.run_on_start):
                await asyncio.sleep(job.interval_seconds * random.uniform(0.95, 1.05))  # jitter avoids synchronised bursts
            first = False
            try:
                await job.run()
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                event(log, "scheduled_job_failed", logging.ERROR, job=job.name, exc_type=type(exc).__name__)

    async def stop(self) -> None:
        for t in self._tasks:
            t.cancel()
        await asyncio.gather(*self._tasks, return_exceptions=True)
