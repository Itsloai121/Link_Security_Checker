from __future__ import annotations

from collections.abc import Awaitable, Callable

from bootstrap.dependency_wiring import Container


def make_scan_handler(c: Container) -> Callable[[str], Awaitable[None]]:
    async def handle(scan_id: str) -> None:
        await c.run_analysis.execute(scan_id)
    return handle
