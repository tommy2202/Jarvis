from __future__ import annotations

from typing import Any, Dict, Set, Tuple


def migrate(files: Dict[str, Dict[str, Any]]) -> Tuple[Dict[str, Dict[str, Any]], Set[str]]:
    """
    Normalize modules.json and modules_registry.json schema (idempotent).
    """
    out = dict(files)
    changed: Set[str] = set()

    modules_raw = out.get("modules.json") or {}
    if not isinstance(modules_raw, dict):
        modules_raw = {}
        changed.add("modules.json")
    if int(modules_raw.get("schema_version") or 0) < 1:
        modules_raw["schema_version"] = 1
        changed.add("modules.json")
    modules_raw.setdefault("intents", [])
    modules_raw.setdefault("modules", {})
    if isinstance(modules_raw.get("modules"), list):
        upgraded: Dict[str, Any] = {}
        for item in modules_raw.get("modules") or []:
            if not isinstance(item, dict):
                continue
            mid = item.get("module_id") or item.get("id") or item.get("module")
            if mid:
                upgraded[str(mid)] = dict(item)
        modules_raw["modules"] = upgraded
        changed.add("modules.json")
    if not isinstance(modules_raw.get("modules"), dict):
        modules_raw["modules"] = {}
        changed.add("modules.json")
    out["modules.json"] = modules_raw

    reg_raw = out.get("modules_registry.json") or {}
    if not isinstance(reg_raw, dict):
        reg_raw = {}
        changed.add("modules_registry.json")
    if not isinstance(reg_raw.get("modules"), list):
        reg_raw["modules"] = []
        changed.add("modules_registry.json")
    out["modules_registry.json"] = reg_raw

    return out, changed
