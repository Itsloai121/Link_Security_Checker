"""Scheduled maintenance handlers (retention purge, threat-feed refresh)."""
from __future__ import annotations

from bootstrap.dependency_wiring import Container


async def purge_expired_scans(c: Container) -> int:
    return await c.purge_scans.execute()


async def refresh_threat_feeds(c: Container) -> list:
    return await c.refresh_feeds.execute()
