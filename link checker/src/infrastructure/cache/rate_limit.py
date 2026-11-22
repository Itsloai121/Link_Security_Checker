"""Sliding-window rate limiter held in memory (a derived, disposable cache - USDA §16).

Bounded by `max_keys` so an attacker rotating client addresses cannot exhaust memory. State is lost on restart,
which is acceptable: limits are an abuse brake, not an accounting record.
"""
from __future__ import annotations

import time
from collections import OrderedDict, deque


class SlidingWindowLimiter:
    def __init__(self, limit: int, window_seconds: float, max_keys: int = 20_000, clock=time.monotonic):
        self.limit, self.window, self.max_keys, self._clock = limit, window_seconds, max_keys, clock
        self._hits: OrderedDict[str, deque[float]] = OrderedDict()

    def check(self, key: str) -> tuple[bool, int]:
        """Record an attempt. Returns (allowed, retry_after_seconds)."""
        now = self._clock()
        dq = self._hits.get(key)
        if dq is None:
            dq = self._hits[key] = deque()
            while len(self._hits) > self.max_keys:
                self._hits.popitem(last=False)  # evict least recently inserted
        else:
            self._hits.move_to_end(key)
        while dq and now - dq[0] >= self.window:
            dq.popleft()
        if len(dq) >= self.limit:
            return False, max(1, int(self.window - (now - dq[0])) + 1)
        dq.append(now)
        return True, 0

    def __len__(self) -> int:
        return len(self._hits)
