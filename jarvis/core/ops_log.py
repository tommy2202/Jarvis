from __future__ import annotations

import json
import os
import threading
import time
from dataclasses import dataclass
from typing import Any, Dict, Optional

from jarvis.core.events import redact


@dataclass(frozen=True)
class OpsLogger:
    """
    Dedicated ops log (JSONL) for shutdown/restart orchestration.
    """

    path: str = os.path.join("logs", "ops.jsonl")
    _lock: threading.Lock = threading.Lock()

    def log(self, *, trace_id: str, event: str, outcome: str, details: Optional[Dict[str, Any]] = None) -> None:
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        payload = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "trace_id": trace_id,
            "event": event,
            "outcome": outcome,
            "details": redact(details or {}),
        }
        line = json.dumps(payload, ensure_ascii=False)
        with self._lock:
            with open(self.path, "a", encoding="utf-8") as f:
                f.write(line + "\n")
                try:
                    f.flush()
                    os.fsync(f.fileno())
                except Exception:
                    pass

