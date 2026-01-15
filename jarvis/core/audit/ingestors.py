from __future__ import annotations

import calendar
import json
import os
import time
from typing import Any, Dict, Iterable, Optional

from jarvis.core.audit.models import (
    Actor,
    ActorSource,
    ActorUser,
    AuditCategory,
    AuditEvent,
    AuditOutcome,
    AuditSeverity,
)
from jarvis.core.audit.redaction import redact_details


def _parse_ts(v: Any) -> float:
    """
    Parse timestamps from JSONL logs.

    Supports:
    - epoch seconds (int/float)
    - ISO8601 'YYYY-mm-ddTHH:MM:SSZ' (used by Jarvis loggers)
    """
    if v is None:
        return float(time.time())
    if isinstance(v, (int, float)):
        return float(v)
    s = str(v or "").strip()
    if not s:
        return float(time.time())
    try:
        return float(s)
    except Exception:
        pass
    try:
        ts = time.strptime(s, "%Y-%m-%dT%H:%M:%SZ")
        return float(calendar.timegm(ts))
    except Exception:
        return float(time.time())


def audit_from_core_event(ev: Any) -> Optional[AuditEvent]:
    """
    Convert internal BaseEvent (event bus) to AuditEvent (privacy-safe).
    """
    try:
        et = str(getattr(ev, "event_type"))
        trace_id = getattr(ev, "trace_id", None)
        payload = getattr(ev, "payload", {}) or {}
        src = str(getattr(getattr(ev, "source_subsystem", None), "value", None) or getattr(ev, "source_subsystem", "system"))
        sev = str(getattr(getattr(ev, "severity", None), "value", None) or getattr(ev, "severity", "INFO"))
    except Exception:
        return None

    # Map to categories/actions/outcomes
    category = AuditCategory.lifecycle
    action = et
    outcome = AuditOutcome.success
    summary = et

    if et == "state.transition":
        category = AuditCategory.lifecycle
        action = "state.transition"
        outcome = AuditOutcome.success
        summary = f"State transition: {payload.get('from')} -> {payload.get('to')}"
    elif et in {"intent.routed", "intent.denied"}:
        category = AuditCategory.permission if et == "intent.denied" else AuditCategory.execution
        action = "intent.execute" if et == "intent.routed" else "intent.denied"
        outcome = AuditOutcome.denied if et == "intent.denied" else AuditOutcome.success
        iid = payload.get("intent_id")
        summary = f"Intent {action}: {iid}"
    elif et == "capability.decision":
        category = AuditCategory.permission
        action = "capability.decision"
        allowed = bool(payload.get("allowed", False))
        outcome = AuditOutcome.success if allowed else AuditOutcome.denied
        summary = f"Capability decision: {'allowed' if allowed else 'denied'} ({payload.get('intent_id')})"
    elif et.startswith("job."):
        category = AuditCategory.job
        action = et
        outcome = AuditOutcome.success if et in {"job.created", "job.started", "job.progress"} else (AuditOutcome.failed if et in {"job.failed", "job.failed_due_to_restart"} else AuditOutcome.success)
        summary = f"Job {et.split('.',1)[1]}: {payload.get('kind') or payload.get('job_id')}"
    elif et.startswith("llm."):
        category = AuditCategory.llm
        action = et
        outcome = AuditOutcome.failed if et == "llm.error" else AuditOutcome.success
        summary = f"LLM {et.split('.',1)[1]}: {payload.get('role')}"
    elif et.startswith("shutdown."):
        category = AuditCategory.lifecycle
        action = et
        outcome = AuditOutcome.success
        summary = f"Shutdown: {et.split('.',1)[1]}"
    elif et == "error.raised":
        category = AuditCategory.error
        action = "error.raised"
        outcome = AuditOutcome.failed
        summary = f"Error: {(payload.get('code') or payload.get('type') or 'error')}"
    elif et == "recovery.action":
        category = AuditCategory.recovery
        action = "recovery.action"
        outcome = AuditOutcome.success
        summary = f"Recovery: {payload.get('action')}"
    elif et == "telemetry.health_change":
        category = AuditCategory.lifecycle
        action = "health_change"
        outcome = AuditOutcome.success
        summary = f"Health change: {payload.get('subsystem')} {payload.get('from')} -> {payload.get('to')}"
    elif et.startswith("resource."):
        category = AuditCategory.lifecycle
        action = et
        outcome = AuditOutcome.denied if "denied" in et else AuditOutcome.success
        summary = f"Resource: {et}"
    elif et == "policy.decision":
        category = AuditCategory.permission
        action = "policy.decision"
        allowed = bool(payload.get("allowed", True))
        outcome = AuditOutcome.success if allowed else AuditOutcome.denied
        summary = f"Policy decision: {'allowed' if allowed else 'denied'} ({payload.get('intent_id')})"
    elif et.startswith("module."):
        # Module lifecycle / configuration changes (manifest/registry).
        category = AuditCategory.config
        action = et
        # outcomes for explicit deny events
        if "denied" in et or "disabled" in et or "missing" in et:
            outcome = AuditOutcome.denied if "denied" in et else AuditOutcome.success
        summary = f"Module: {et.split('.', 1)[1]} ({payload.get('module_id')})"

    actor_source = ActorSource.system
    if src in {"web", "ui", "cli", "voice"}:
        actor_source = ActorSource(src)

    # severity mapping
    sev_map = {"INFO": AuditSeverity.INFO, "WARN": AuditSeverity.WARN, "ERROR": AuditSeverity.ERROR, "CRITICAL": AuditSeverity.CRITICAL}
    severity = sev_map.get(sev.upper(), AuditSeverity.INFO)

    details = redact_details(category.value, action, dict(payload) if isinstance(payload, dict) else {})
    uid = None
    try:
        uid = str(payload.get("user_id") or "") if isinstance(payload, dict) else ""
        uid = uid or None
    except Exception:
        uid = None

    return AuditEvent(
        timestamp=float(getattr(ev, "timestamp", None) or time.time()),
        trace_id=str(trace_id) if trace_id else None,
        actor=Actor(source=actor_source, user=ActorUser.unknown, user_id=uid),
        category=category,
        action=str(action),
        outcome=outcome,
        summary=str(summary)[:200],
        details=details,
        severity=severity,
    )


def iter_jsonl_new(path: str, *, start_offset: int) -> tuple[int, Iterable[Dict[str, Any]]]:
    """
    Returns (new_offset, iterable_of_objects) reading from start_offset.
    """
    if not os.path.exists(path):
        return start_offset, []

    def _gen():
        with open(path, "rb") as f:
            try:
                f.seek(int(start_offset))
            except Exception:
                f.seek(0)
            while True:
                line = f.readline()
                if not line:
                    break
                try:
                    obj = json.loads(line.decode("utf-8", errors="ignore"))
                except Exception:
                    continue
                if isinstance(obj, dict):
                    yield obj

    try:
        with open(path, "rb") as f2:
            f2.seek(0, os.SEEK_END)
            end = int(f2.tell())
    except Exception:
        end = start_offset
    return end, _gen()


def audit_from_security_log(obj: Dict[str, Any]) -> Optional[AuditEvent]:
    try:
        trace_id = str(obj.get("trace_id") or "")
        event = str(obj.get("event") or "security.event")
        outcome = str(obj.get("outcome") or "success")
        severity = str(obj.get("severity") or "INFO")
        details = dict(obj.get("details") or {})
        ip = obj.get("ip")
    except Exception:
        return None

    oc = AuditOutcome.success
    if outcome in {"denied", "failed"}:
        oc = AuditOutcome.denied if outcome == "denied" else AuditOutcome.failed
    sev_map = {"INFO": AuditSeverity.INFO, "WARN": AuditSeverity.WARN, "ERROR": AuditSeverity.ERROR, "HIGH": AuditSeverity.WARN, "CRITICAL": AuditSeverity.CRITICAL}
    sev = sev_map.get(severity.upper(), AuditSeverity.INFO)
    safe_details = redact_details("security", event, {"ip": ip, **details})
    return AuditEvent(
        timestamp=_parse_ts(obj.get("ts")),
        trace_id=trace_id or None,
        actor=Actor(source=ActorSource.web, user=ActorUser.unknown),
        category=AuditCategory.security,
        action=event,
        outcome=oc,
        summary=f"Security: {event}",
        details=safe_details,
        severity=sev,
    )


def audit_from_ops_log(obj: Dict[str, Any]) -> Optional[AuditEvent]:
    try:
        trace_id = str(obj.get("trace_id") or "")
        event = str(obj.get("event") or "ops.event")
        outcome = str(obj.get("outcome") or "success")
        details = dict(obj.get("details") or {})
    except Exception:
        return None
    oc = AuditOutcome.success if outcome == "ok" or outcome == "success" else AuditOutcome.failed
    return AuditEvent(
        timestamp=_parse_ts(obj.get("ts")),
        trace_id=trace_id or None,
        actor=Actor(source=ActorSource.system, user=ActorUser.unknown),
        category=AuditCategory.lifecycle,
        action=event,
        outcome=oc,
        summary=f"Ops: {event}",
        details=redact_details("lifecycle", event, details),
        severity=AuditSeverity.INFO if oc == AuditOutcome.success else AuditSeverity.WARN,
    )


def audit_from_errors_log(obj: Dict[str, Any]) -> Optional[AuditEvent]:
    try:
        trace_id = str(obj.get("trace_id") or "")
        code = str(obj.get("error_code") or obj.get("code") or "error")
        subsystem = str(obj.get("subsystem") or "unknown")
        sev = str(obj.get("severity") or "ERROR")
    except Exception:
        return None
    sev_map = {"INFO": AuditSeverity.INFO, "WARN": AuditSeverity.WARN, "ERROR": AuditSeverity.ERROR, "CRITICAL": AuditSeverity.CRITICAL}
    return AuditEvent(
        timestamp=_parse_ts(obj.get("timestamp") or obj.get("ts")),
        trace_id=trace_id or None,
        actor=Actor(source=ActorSource.system, user=ActorUser.unknown),
        category=AuditCategory.error,
        action="error.raised",
        outcome=AuditOutcome.failed,
        summary=f"Error: {subsystem}.{code}",
        details=redact_details("error", "error.raised", {"subsystem": subsystem, "code": code}),
        severity=sev_map.get(sev.upper(), AuditSeverity.ERROR),
    )

