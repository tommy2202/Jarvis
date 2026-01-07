from __future__ import annotations

import threading
from dataclasses import dataclass, field
from typing import Dict


@dataclass
class EventBusStats:
    published_total: int = 0
    dropped_total: int = 0
    handler_errors_total: int = 0
    delivered_total: int = 0
    queue_depth: int = 0
    subscribers: int = 0
    per_type_published: Dict[str, int] = field(default_factory=dict)


class StatsCounter:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._stats = EventBusStats()

    def snapshot(self) -> EventBusStats:
        with self._lock:
            s = self._stats
            return EventBusStats(
                published_total=s.published_total,
                dropped_total=s.dropped_total,
                handler_errors_total=s.handler_errors_total,
                delivered_total=s.delivered_total,
                queue_depth=s.queue_depth,
                subscribers=s.subscribers,
                per_type_published=dict(s.per_type_published),
            )

    def inc_published(self, event_type: str) -> None:
        with self._lock:
            self._stats.published_total += 1
            self._stats.per_type_published[event_type] = int(self._stats.per_type_published.get(event_type, 0) + 1)

    def inc_dropped(self, n: int = 1) -> None:
        with self._lock:
            self._stats.dropped_total += int(n)

    def inc_delivered(self, n: int = 1) -> None:
        with self._lock:
            self._stats.delivered_total += int(n)

    def inc_handler_error(self, n: int = 1) -> None:
        with self._lock:
            self._stats.handler_errors_total += int(n)

    def set_queue_depth(self, n: int) -> None:
        with self._lock:
            self._stats.queue_depth = int(n)

    def set_subscribers(self, n: int) -> None:
        with self._lock:
            self._stats.subscribers = int(n)

