from __future__ import annotations

from typing import Any, Dict, List, Optional

from jarvis.core.resources.models import AdmissionDecision


def governor_admit_for_caps(
    governor: Any,
    *,
    trace_id: str,
    operation: str,
    required_caps: List[str],
    allow_delay: bool,
) -> Optional[AdmissionDecision]:
    if governor is None:
        return None
    try:
        return governor.admit(operation=operation, trace_id=trace_id, required_caps=required_caps, allow_delay=allow_delay)
    except Exception:
        return None

