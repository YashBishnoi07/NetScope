from __future__ import annotations

from collections import deque
from typing import Generic, TypeVar

T = TypeVar("T")


class RingBuffer(Generic[T]):
    def __init__(self, max_size: int) -> None:
        if max_size <= 0:
            raise ValueError("max_size must be positive")
        self.max_size = max_size
        self._items: deque[tuple[int, T]] = deque(maxlen=max_size)
        self._next_id = 1

    @property
    def next_id(self) -> int:
        return self._next_id

    def append(self, item: T) -> int:
        packet_id = self._next_id
        self._next_id += 1
        self._items.append((packet_id, item))
        return packet_id

    def get(self, packet_id: int) -> T | None:
        for item_id, item in self._items:
            if item_id == packet_id:
                return item
        return None

    def slice(self, after_id: int, limit: int = 50) -> list[T]:
        if limit <= 0:
            return []
        result: list[T] = []
        for item_id, item in self._items:
            if item_id > after_id:
                result.append(item)
                if len(result) >= limit:
                    break
        return result

    def snapshot(self) -> list[T]:
        return [item for _, item in self._items]

    def __len__(self) -> int:
        return len(self._items)
