from __future__ import annotations

import json
import os
import threading
import time
from dataclasses import dataclass
from typing import Any, Dict, Optional


REDACT_KEYS = {
    "passphrase",
    "password",
    "secret",
    "token",
    "api_key",
    "key",
    "master_key",
    "usb_key",
    "authorization",
}


def _redact(obj: Any) -> Any:
    if isinstance(obj, dict):
        out: Dict[str, Any] = {}
        for k, v in obj.items():
            if str(k).lower() in REDACT_KEYS:
                out[k] = "***REDACTED***"
            else:
                out[k] = _redact(v)
        return out
    if isinstance(obj, list):
        return [_redact(x) for x in obj]
    return obj


# Exported helper for other subsystems (job manager, etc.)
def redact(obj: Any) -> Any:
    return _redact(obj)


@dataclass(frozen=True)
class EventLogger:
    path: str
    _lock: threading.Lock = threading.Lock()

    def log(self, trace_id: str, event_type: str, details: Optional[Dict[str, Any]] = None) -> None:
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        payload = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "trace_id": trace_id,
            "event": event_type,
            "details": _redact(details or {}),
        }
        line = json.dumps(payload, ensure_ascii=False)
        with self._lock:
            with open(self.path, "a", encoding="utf-8") as f:
                f.write(line + "\n")

