from __future__ import annotations

from collections import deque
from typing import Deque, Tuple


class TimeWindow:
    def __init__(self) -> None:
        self._samples: Deque[Tuple[float, float]] = deque()

    def add(self, timestamp: float, value: float) -> None:
        self._samples.append((float(timestamp), float(value)))

    def sum(self, window_seconds: float) -> float:
        cutoff = self._samples[-1][0] - window_seconds if self._samples else 0.0
        total = 0.0
        for ts, value in self._samples:
            if ts >= cutoff:
                total += value
        return total

    def series(self, window_seconds: float, points: int = 12) -> list[float]:
        if not self._samples:
            return [0.0 for _ in range(points)]
        latest = self._samples[-1][0]
        bucket_size = max(window_seconds / points, 0.001)
        buckets = [0.0 for _ in range(points)]
        for ts, value in self._samples:
            elapsed = latest - ts
            if elapsed > window_seconds:
                continue
            idx = min(points - 1, max(0, int(elapsed / bucket_size)))
            buckets[points - 1 - idx] += value
        return buckets
