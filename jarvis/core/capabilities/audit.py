from __future__ import annotations

import threading
from collections import deque
from typing import Any, Deque, Dict, List, Optional

from jarvis.core.capabilities.redaction import redact_audit
from jarvis.core.security_events import SecurityAuditLogger


class CapabilityAuditLogger:
    """
    Writes capability decisions to logs/security.jsonl and retains a small in-memory tail for UI.
    """

    def __init__(self, *, path: str = "logs/security.jsonl", keep_last: int = 200):
        self._audit = SecurityAuditLogger(path=path)
        self._lock = threading.Lock()
        self._recent: Deque[Dict[str, Any]] = deque(maxlen=max(50, int(keep_last)))

    def log_decision(self, *, trace_id: str, severity: str, event: str, outcome: str, details: Dict[str, Any], ip: Optional[str] = None, endpoint: str = "capabilities") -> None:
        safe = redact_audit(details or {})
        self._audit.log(trace_id=trace_id, severity=severity, event=event, ip=ip, endpoint=endpoint, outcome=outcome, details=safe)
        with self._lock:
            self._recent.appendleft({"trace_id": trace_id, "severity": severity, "event": event, "outcome": outcome, "details": safe})

    def recent(self, n: int = 50) -> List[Dict[str, Any]]:
        with self._lock:
            return list(self._recent)[: max(1, int(n))]

