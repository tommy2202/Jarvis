from __future__ import annotations

import json
import os
import threading
from collections import deque
from typing import Any, Deque, Dict, List, Optional

from jarvis.core.telemetry.models import HealthEvent
from jarvis.core.telemetry.redaction import telemetry_redact


class TelemetryEventWriter:
    def __init__(self, *, events_path: str = os.path.join("logs", "telemetry", "health_events.jsonl"), keep_last: int = 200):
        self.events_path = events_path
        self._lock = threading.Lock()
        os.makedirs(os.path.dirname(self.events_path), exist_ok=True)
        self._recent: Deque[HealthEvent] = deque(maxlen=max(20, int(keep_last)))

    def emit(self, ev: HealthEvent) -> None:
        safe = HealthEvent.model_validate({"ts": ev.ts, "trace_id": ev.trace_id, "event_type": ev.event_type, "subsystem": ev.subsystem, "old_status": ev.old_status, "new_status": ev.new_status, "message": ev.message, "details": telemetry_redact(ev.details or {})})
        line = json.dumps(safe.model_dump(), ensure_ascii=False)
        with self._lock:
            with open(self.events_path, "a", encoding="utf-8") as f:
                f.write(line + "\n")
            self._recent.appendleft(safe)

    def recent(self, n: int = 20) -> List[Dict[str, Any]]:
        with self._lock:
            return [x.model_dump() for x in list(self._recent)[: max(1, int(n))]]

