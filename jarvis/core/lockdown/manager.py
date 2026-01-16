from __future__ import annotations

from collections import deque
from dataclasses import dataclass
import threading
import time
from typing import Any, Deque, Dict, Optional

from jarvis.core.errors import AdminRequiredError
from jarvis.core.events import redact
from jarvis.core.events.models import BaseEvent, EventSeverity, SourceSubsystem
from jarvis.core.security_events import SecurityAuditLogger
from jarvis.core.trace import resolve_trace_id


@dataclass(frozen=True)
class LockdownConfig:
    admin_failure_threshold: int = 3
    admin_failure_window_seconds: float = 60.0
    deny_burst_threshold: int = 10
    deny_burst_window_seconds: float = 10.0


class LockdownManager:
    def __init__(
        self,
        *,
        cfg: Optional[LockdownConfig] = None,
        security_manager: Any = None,
        audit_logger: Optional[SecurityAuditLogger] = None,
        event_bus: Any = None,
        logger=None,
        now: Any = None,
    ) -> None:
        self.cfg = cfg or LockdownConfig()
        self.security_manager = security_manager
        self.audit_logger = audit_logger or SecurityAuditLogger()
        self.event_bus = event_bus
        self.logger = logger
        self._now = now or time.time
        self._lock = threading.Lock()
        self._admin_failures: Deque[float] = deque()
        self._deny_events: Deque[float] = deque()
        self._active = False
        self._reason = ""
        self._entered_at: Optional[float] = None

    def is_active(self) -> bool:
        with self._lock:
            return bool(self._active)

    def status(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "active": bool(self._active),
                "reason": self._reason,
                "entered_at": self._entered_at,
                "admin_failures_recent": len(self._admin_failures),
                "deny_events_recent": len(self._deny_events),
                "thresholds": {
                    "admin_failure_threshold": int(self.cfg.admin_failure_threshold),
                    "admin_failure_window_seconds": float(self.cfg.admin_failure_window_seconds),
                    "deny_burst_threshold": int(self.cfg.deny_burst_threshold),
                    "deny_burst_window_seconds": float(self.cfg.deny_burst_window_seconds),
                },
            }

    def record_admin_failure(self, *, trace_id: Optional[str] = None, source: str = "local", details: Optional[Dict[str, Any]] = None) -> None:
        trace_id = resolve_trace_id(trace_id)
        count = self._record_event(self._admin_failures, float(self.cfg.admin_failure_window_seconds))
        if count >= int(self.cfg.admin_failure_threshold):
            self._enter_lockdown(
                trace_id=trace_id,
                reason="admin_failures",
                details={"count": count, "source": source, **(details or {})},
                source_subsystem=SourceSubsystem.state_machine,
            )

    def record_admin_success(self) -> None:
        with self._lock:
            self._admin_failures.clear()

    def record_deny(
        self,
        *,
        trace_id: Optional[str] = None,
        intent_id: str = "",
        module_id: str = "",
        denied_reason: str = "",
        source: str = "dispatcher",
    ) -> None:
        if denied_reason == "lockdown_active":
            return
        trace_id = resolve_trace_id(trace_id)
        count = self._record_event(self._deny_events, float(self.cfg.deny_burst_window_seconds))
        if count >= int(self.cfg.deny_burst_threshold):
            self._enter_lockdown(
                trace_id=trace_id,
                reason="deny_burst",
                details={"count": count, "intent_id": intent_id, "module_id": module_id, "denied_reason": denied_reason, "source": source},
                source_subsystem=SourceSubsystem.dispatcher,
            )

    def enter_lockdown(self, *, trace_id: Optional[str] = None, reason: str = "manual", details: Optional[Dict[str, Any]] = None) -> None:
        trace_id = resolve_trace_id(trace_id)
        self._enter_lockdown(trace_id=trace_id, reason=reason, details=details or {}, source_subsystem=SourceSubsystem.state_machine)

    def exit_lockdown(self, *, trace_id: Optional[str] = None, actor: str = "admin", reason: str = "manual") -> bool:
        if self.security_manager is not None and not bool(getattr(self.security_manager, "is_admin", lambda: False)()):
            raise AdminRequiredError("Admin required to exit lockdown.")
        trace_id = resolve_trace_id(trace_id)
        with self._lock:
            if not self._active:
                return False
            self._active = False
            self._reason = ""
            self._entered_at = None
            self._admin_failures.clear()
            self._deny_events.clear()
        self._emit_audit(
            trace_id=trace_id,
            event="security.lockdown_exited",
            outcome="exited",
            details={"actor": actor, "reason": reason},
            severity=EventSeverity.INFO,
            source_subsystem=SourceSubsystem.state_machine,
        )
        return True

    # ---- internals ----
    def _record_event(self, bucket: Deque[float], window_seconds: float) -> int:
        now = float(self._now())
        cutoff = now - max(0.0, window_seconds)
        with self._lock:
            bucket.append(now)
            while bucket and bucket[0] < cutoff:
                bucket.popleft()
            return len(bucket)

    def _enter_lockdown(
        self,
        *,
        trace_id: str,
        reason: str,
        details: Dict[str, Any],
        source_subsystem: SourceSubsystem,
    ) -> None:
        with self._lock:
            if self._active:
                return
            self._active = True
            self._reason = str(reason or "unknown")
            self._entered_at = float(self._now())
            self._admin_failures.clear()
            self._deny_events.clear()
        self._emit_audit(
            trace_id=trace_id,
            event="security.lockdown_entered",
            outcome="entered",
            details={"reason": reason, **(details or {})},
            severity=EventSeverity.WARN,
            source_subsystem=source_subsystem,
        )

    def _emit_audit(
        self,
        *,
        trace_id: str,
        event: str,
        outcome: str,
        details: Dict[str, Any],
        severity: EventSeverity,
        source_subsystem: SourceSubsystem,
    ) -> None:
        try:
            self.audit_logger.log(
                trace_id=trace_id,
                severity=severity.value,
                event=event,
                ip=None,
                endpoint="lockdown",
                outcome=outcome,
                details=details,
            )
        except Exception:
            pass
        if self.event_bus is not None:
            try:
                self.event_bus.publish_nowait(
                    BaseEvent(
                        event_type=event,
                        trace_id=trace_id,
                        source_subsystem=source_subsystem,
                        severity=severity,
                        payload=redact(details),
                    )
                )
            except Exception:
                pass
