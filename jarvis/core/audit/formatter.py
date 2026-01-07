from __future__ import annotations

import time

from jarvis.core.audit.models import AuditEvent


def format_line(ev: AuditEvent) -> str:
    ts = time.strftime("%H:%M:%S", time.localtime(float(ev.timestamp)))
    out = f"{ts} — {ev.summary} — {ev.outcome.value}"
    if ev.severity.value in {"WARN", "ERROR", "CRITICAL"}:
        out = f"{out} [{ev.severity.value}]"
    return out

