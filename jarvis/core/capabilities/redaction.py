from __future__ import annotations

from typing import Any

from jarvis.core.events import redact as redact_by_key
from jarvis.core.telemetry.redaction import telemetry_redact


def redact_audit(obj: Any) -> Any:
    """
    Capability audit redaction:
    - key-based secret redaction (shared)
    - inline secret scrubbing (shared telemetry redaction)
    """
    return telemetry_redact(redact_by_key(obj))

