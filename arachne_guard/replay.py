"""Replay protection: bounded nonce cache with a clock-skew window.

A nonce is remembered until ``ts + window``: after that, the timestamp check
alone rejects any replay. The cache is bounded and fails closed when full.
"""
from __future__ import annotations

import heapq
import time
from typing import Callable, Dict, List, Tuple


class ReplayGuard:
    def __init__(self, window_seconds: float = 60.0, max_entries: int = 10_000,
                 clock: Callable[[], float] = time.time):
        if window_seconds <= 0 or max_entries < 1:
            raise ValueError("window_seconds must be > 0 and max_entries >= 1")
        self.window = window_seconds
        self.max_entries = max_entries
        self._clock = clock
        self._seen: Dict[Tuple[str, str], float] = {}
        self._heap: List[Tuple[float, Tuple[str, str]]] = []

    def check(self, agent_id: str, nonce: object, ts: object) -> Tuple[bool, str]:
        if not isinstance(nonce, str) or not 8 <= len(nonce) <= 128:
            return False, "nonce must be a string of 8 to 128 characters"
        if isinstance(ts, bool) or not isinstance(ts, (int, float)):
            return False, "timestamp must be a number"
        now = self._clock()
        if abs(now - ts) > self.window:
            return False, "timestamp outside allowed window"
        self._evict(now)
        key = (agent_id, nonce)
        if key in self._seen:
            return False, "replayed nonce"
        if len(self._seen) >= self.max_entries:
            return False, "replay cache full"
        expiry = ts + self.window
        self._seen[key] = expiry
        heapq.heappush(self._heap, (expiry, key))
        return True, "ok"

    def _evict(self, now: float) -> None:
        while self._heap and self._heap[0][0] < now:
            expiry, key = heapq.heappop(self._heap)
            if self._seen.get(key) == expiry:
                del self._seen[key]

    def __len__(self) -> int:
        return len(self._seen)
