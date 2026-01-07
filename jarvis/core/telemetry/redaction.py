from __future__ import annotations

import re
from typing import Any, Dict

from jarvis.core.events import redact as redact_by_key


_SENSITIVE_INLINE = [
    # e.g. "api_key: abc", "token=xyz"
    re.compile(r"(?i)\b(api[_-]?key|token|secret|passphrase|password|authorization)\b\s*[:=]\s*([^\s,;]+)"),
    # e.g. "Bearer <token>"
    re.compile(r"(?i)\bBearer\s+([A-Za-z0-9\-\._~\+/]+=*)"),
]


def _redact_string(s: str) -> str:
    out = s
    # bearer token patterns (do first so "Authorization: Bearer <token>" is fully scrubbed)
    out = _SENSITIVE_INLINE[1].sub("Bearer ***REDACTED***", out)
    # key/value patterns
    out = _SENSITIVE_INLINE[0].sub(lambda m: f"{m.group(1)}=***REDACTED***", out)
    return out


def telemetry_redact(obj: Any) -> Any:
    """
    Telemetry-safe redaction:
    - key-based redaction (shared with event logs)
    - inline string scrubbing for common secret patterns
    """
    if obj is None:
        return None
    if isinstance(obj, str):
        return _redact_string(obj)
    if isinstance(obj, dict):
        # key-based redaction first
        base: Dict[str, Any] = redact_by_key(obj)
        return {k: telemetry_redact(v) for k, v in base.items()}
    if isinstance(obj, list):
        return [telemetry_redact(x) for x in obj]
    return obj

