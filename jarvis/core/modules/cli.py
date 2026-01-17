from __future__ import annotations

"""
CLI rendering helpers for /modules commands.

WHY THIS FILE EXISTS:
The CLI loop in app.py is intentionally simple; these helpers provide a stable,
testable rendering surface for module status without importing/executing modules.
"""

import json
import os
from typing import Any, Dict, List

from jarvis.core.modules.models import ModuleStatus
from jarvis.core.modules.wizard import validate_manifest_dict


def modules_list_lines(*, module_manager: Any, trace_id: str = "cli") -> List[str]:
    """
    Render /modules list output lines.
    Columns: module_id | state | enabled | reason_code | remediation
    """
    statuses: List[ModuleStatus] = list(getattr(module_manager, "list_status")(trace_id=trace_id) or [])
    reg = {}
    try:
        raw = module_manager.list_registry()
        reg = (raw.get("modules") or {}) if isinstance(raw, dict) else {}
    except Exception:
        reg = {}
    if not isinstance(reg, dict):
        reg = {}

    lines = ["module_id | state | enabled | reason_code | remediation"]
    for st in statuses:
        rec = reg.get(st.module_id) if isinstance(reg, dict) else None
        enabled = bool(rec.get("enabled")) if isinstance(rec, dict) else False
        lines.append(f"{st.module_id} | {st.state.value} | {str(enabled).lower()} | {st.reason_code.value} | {st.remediation}")
    return lines


def modules_status_lines(*, module_manager: Any, trace_id: str = "cli") -> List[str]:
    """
    Render /modules status output lines (more verbose than list).
    Columns: module_id | state | enabled | reason_code | reason | remediation
    """
    statuses: List[ModuleStatus] = list(getattr(module_manager, "list_status")(trace_id=trace_id) or [])
    reg = {}
    try:
        raw = module_manager.list_registry()
        reg = (raw.get("modules") or {}) if isinstance(raw, dict) else {}
    except Exception:
        reg = {}
    if not isinstance(reg, dict):
        reg = {}

    lines = ["module_id | state | enabled | reason_code | reason | remediation"]
    for st in statuses:
        rec = reg.get(st.module_id) if isinstance(reg, dict) else None
        enabled = bool(rec.get("enabled")) if isinstance(rec, dict) else False
        reason = str(st.reason_human or "")
        lines.append(f"{st.module_id} | {st.state.value} | {str(enabled).lower()} | {st.reason_code.value} | {reason} | {st.remediation}")
    return lines


def modules_show_payload(*, module_manager: Any, module_id: str, trace_id: str = "cli") -> Dict[str, Any]:
    """
    Build /modules show output payload: ModuleStatus + manifest summary (no secrets).
    """
    st = getattr(module_manager, "get_status")(str(module_id), trace_id=trace_id)
    summary: Dict[str, Any] = {"ok": False}

    # Best-effort: manifest is expected at <modules_root>/<module_id>/module.json
    mroot = str(getattr(module_manager, "modules_root", "") or "")
    mpath = os.path.join(mroot, str(module_id), "module.json") if mroot else ""
    if mpath and os.path.exists(mpath) and os.path.isfile(mpath):
        try:
            with open(mpath, "r", encoding="utf-8") as f:
                raw = json.load(f)
        except Exception as e:  # noqa: BLE001
            raw = None
            summary = {"ok": False, "error": f"read_failed: {str(e)[:120]}"}
        if isinstance(raw, dict):
            man, err = validate_manifest_dict(raw)
            if man is None:
                summary = {"ok": False, "error": ("manifest_invalid: " + str(err or ""))[:200], "module_id": str(raw.get("module_id") or "")}
            else:
                summary = {
                    "ok": True,
                    "module_id": man.module_id,
                    "version": man.version,
                    "entrypoint": man.entrypoint,
                    "intents": [
                        {
                            "intent_id": it.intent_id,
                            "required_capabilities": list(it.required_capabilities or []),
                            "resource_class": it.resource_class.value,
                            "execution_mode": it.execution_mode.value,
                        }
                        for it in (man.intents or [])
                    ],
                    "module_defaults": {
                        "enabled_by_default": bool(man.module_defaults.enabled_by_default),
                        "admin_required_to_enable": bool(man.module_defaults.admin_required_to_enable),
                    },
                }
    else:
        summary = {"ok": False, "error": "module.json not found"}

    return {"status": st.model_dump(), "manifest_summary": summary}

