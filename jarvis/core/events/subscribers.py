from __future__ import annotations

import json
import os
import threading
import time
from collections import deque
from dataclasses import dataclass
from typing import Any, Callable, Deque, Dict, List, Optional

from jarvis.core.events.models import BaseEvent, EventSeverity, SourceSubsystem


EventHandler = Callable[[BaseEvent], None]


@dataclass
class Subscriber:
    handler: EventHandler
    event_type: str
    priority: int = 50


class CoreEventJsonlSubscriber:
    """
    Writes all events to logs/events/core_events.jsonl (redacted payload only).
    """

    def __init__(self, *, path: str = os.path.join("logs", "events", "core_events.jsonl")):
        self.path = path
        self._lock = threading.Lock()
        os.makedirs(os.path.dirname(self.path), exist_ok=True)

    def __call__(self, ev: BaseEvent) -> None:
        line = json.dumps(ev.model_dump(), ensure_ascii=False)
        with self._lock:
            with open(self.path, "a", encoding="utf-8") as f:
                f.write(line + "\n")


class DebugPrintSubscriber:
    def __init__(self, *, enabled: bool = False):
        self.enabled = bool(enabled)

    def __call__(self, ev: BaseEvent) -> None:
        if not self.enabled:
            return
        print(f"[{ev.source_subsystem}] {ev.event_type} {ev.severity}: {ev.payload}")

