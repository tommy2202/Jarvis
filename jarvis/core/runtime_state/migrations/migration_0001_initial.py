from __future__ import annotations

from typing import Any, Dict, Tuple


def apply(state: Dict[str, Any]) -> Tuple[Dict[str, Any], bool]:
    """
    Ensure required top-level keys exist for v1.
    """
    changed = False
    out = dict(state or {})
    if int(out.get("state_version") or 0) < 1:
        out["state_version"] = 1
        changed = True
    return out, changed

