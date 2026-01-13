from __future__ import annotations

import json
import os
import threading
from collections import deque
from typing import Any, Deque, Dict, List, Optional

from jarvis.core.telemetry.models import HealthEvent
from jarvis.core.telemetry.redaction import telemetry_redact


class TelemetryEventWriter:
    def __init__(self, *, events_path: str = os.path.join("logs", "telemetry", "health_events.jsonl"), keep_last: int = 200, privacy_store: Any = None):
        self.events_path = events_path
        self.privacy_store = privacy_store
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
        # Privacy inventory (best-effort, no content)
        if self.privacy_store is not None:
            try:
                from jarvis.core.privacy.models import DataCategory, LawfulBasis, Sensitivity
                from jarvis.core.privacy.tagging import data_record_for_file

                self.privacy_store.register_record(
                    data_record_for_file(
                        user_id="default",
                        path=self.events_path,
                        category=DataCategory.TELEMETRY,
                        sensitivity=Sensitivity.LOW,
                        lawful_basis=LawfulBasis.LEGITIMATE_INTERESTS,
                        trace_id=str(getattr(ev, "trace_id", "") or "telemetry"),
                        producer="telemetry",
                        tags={"format": "jsonl"},
                    )
                )
            except Exception:
                pass

    def recent(self, n: int = 20) -> List[Dict[str, Any]]:
        with self._lock:
            return [x.model_dump() for x in list(self._recent)[: max(1, int(n))]]

