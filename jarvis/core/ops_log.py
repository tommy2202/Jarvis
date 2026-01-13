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
    privacy_store: Any = None
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
        # Privacy inventory (best-effort, no content)
        if self.privacy_store is not None:
            try:
                from jarvis.core.privacy.models import DataCategory, LawfulBasis, Sensitivity
                from jarvis.core.privacy.tagging import data_record_for_file

                self.privacy_store.register_record(
                    data_record_for_file(
                        user_id="default",
                        path=self.path,
                        category=DataCategory.OPS_LOG,
                        sensitivity=Sensitivity.LOW,
                        lawful_basis=LawfulBasis.LEGITIMATE_INTERESTS,
                        trace_id=str(trace_id or "ops"),
                        producer="ops_logger",
                        tags={"format": "jsonl"},
                    )
                )
            except Exception:
                pass

