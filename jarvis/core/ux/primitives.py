from __future__ import annotations

from typing import Any, Dict, Iterable, List


def _coerce_text(value: Any, *, limit: int) -> str:
    text = str(value or "").strip()
    if not text:
        return ""
    return text[:limit]


def acknowledge(action: str) -> Dict[str, Any]:
    return {"type": "acknowledge", "action": _coerce_text(action, limit=120)}


def progress(value: int | float | str | None = None) -> Dict[str, Any]:
    payload: Dict[str, Any] = {"type": "progress"}
    if isinstance(value, (int, float)):
        percent = int(round(float(value)))
        payload["percent"] = max(0, min(100, percent))
        return payload
    message = _coerce_text(value, limit=200)
    if message:
        payload["message"] = message
    return payload


def completed(summary: str) -> Dict[str, Any]:
    return {"type": "completed", "summary": _coerce_text(summary, limit=300)}


def failed(reason: str, remediation: str) -> Dict[str, Any]:
    return {
        "type": "failed",
        "reason": _coerce_text(reason, limit=300),
        "remediation": _coerce_text(remediation, limit=300),
    }


def cancel_current() -> Dict[str, Any]:
    return {"type": "cancel_current"}


def render_event(event: Dict[str, Any]) -> str:
    typ = str(event.get("type") or "")
    if typ == "acknowledge":
        action = _coerce_text(event.get("action"), limit=120) or "request"
        return f"Working on {action}."
    if typ == "progress":
        if "percent" in event:
            return f"Progress: {int(event.get('percent') or 0)}%."
        message = _coerce_text(event.get("message"), limit=200)
        return f"Progress: {message}." if message else "Progressing."
    if typ == "completed":
        summary = _coerce_text(event.get("summary"), limit=300)
        return summary if summary else "Completed."
    if typ == "failed":
        reason = _coerce_text(event.get("reason"), limit=300) or "Failed."
        remediation = _coerce_text(event.get("remediation"), limit=300)
        if remediation and remediation not in reason:
            return f"{reason} ({remediation})"
        return reason
    if typ == "cancel_current":
        return "Canceled."
    return _coerce_text(event.get("summary") or event.get("message") or "", limit=300)


def render_events(events: Iterable[Dict[str, Any]] | Dict[str, Any] | None) -> List[str]:
    if not events:
        return []
    if isinstance(events, dict):
        return [render_event(events)]
    return [render_event(ev) for ev in list(events)]
