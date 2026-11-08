"""Per-agent sliding-window rate limiter with an injectable clock."""
from __future__ import annotations

import time
from collections import defaultdict, deque
from typing import Callable, Deque, Dict


class RateLimiter:
    def __init__(self, max_calls: int, window_seconds: float, clock: Callable[[], float] = time.monotonic):
        if max_calls < 1 or window_seconds <= 0:
            raise ValueError("max_calls must be >= 1 and window_seconds > 0")
        self.max_calls = max_calls
        self.window = window_seconds
        self._clock = clock
        self._hits: Dict[str, Deque[float]] = defaultdict(deque)

    def allow(self, key: str) -> bool:
        now = self._clock()
        q = self._hits[key]
        while q and q[0] <= now - self.window:
            q.popleft()
        if len(q) >= self.max_calls:
            return False
        q.append(now)
        return True
