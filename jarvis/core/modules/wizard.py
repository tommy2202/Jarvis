from __future__ import annotations

"""
Module install/repair wizard (non-import).

WHY THIS FILE EXISTS:
Discovery can detect modules, but only the wizard is allowed to create/repair
the manifest contract and update the installed registry. This flow is designed
to be usable non-interactively (auto-template + disabled) and is audit-logged.
"""

import json
import os
import time
from typing import Any, Dict, Optional, Tuple

from jarvis.core.modules.fingerprints import contract_hash_from_manifest_dict
from jarvis.core.modules.models import ModuleManifest


def _iso_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _write_json(path: str, obj: Dict[str, Any]) -> None:
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2, ensure_ascii=False, sort_keys=True)
        f.write("\n")
    os.replace(tmp, path)


def build_template_manifest(*, module_id: str) -> Dict[str, Any]:
    return {
        "schema_version": 1,
        "module_id": module_id,
        "version": "0.1.0",
        "display_name": module_id,
        "description": "",
        # Placeholder only; never imported during discovery.
        "entrypoint": f"jarvis.modules.{module_id.replace('.', '_')}:register",
        "intents": [],
        "module_defaults": {"enabled_by_default": False, "admin_required_to_enable": False},
    }


def validate_manifest_dict(raw: Dict[str, Any]) -> Tuple[Optional[ModuleManifest], str]:
    try:
        man = ModuleManifest.model_validate(raw)
        return man, ""
    except Exception as e:
        return None, str(e)[:300]


def repair_or_create_manifest(*, module_dir: str, module_id: str) -> Tuple[Dict[str, Any], bool, str]:
    """
    Returns: (manifest_dict, wrote_file, status)
    status in: ok|repaired|created|invalid_kept
    """
    manifest_path = os.path.join(module_dir, "module.json")
    if os.path.exists(manifest_path):
        try:
            with open(manifest_path, "r", encoding="utf-8") as f:
                raw = json.load(f)
        except Exception:
            raw = None
        if isinstance(raw, dict):
            # Ensure required keys exist; do not guess contract details.
            changed = False
            if raw.get("schema_version") is None:
                raw["schema_version"] = 1
                changed = True
            if raw.get("module_id") != module_id:
                raw["module_id"] = module_id
                changed = True
            if raw.get("version") is None:
                raw["version"] = "0.1.0"
                changed = True
            if raw.get("display_name") is None:
                raw["display_name"] = module_id
                changed = True
            if raw.get("description") is None:
                raw["description"] = ""
                changed = True
            if raw.get("entrypoint") is None:
                raw["entrypoint"] = f"jarvis.modules.{module_id.replace('.', '_')}:register"
                changed = True
            if raw.get("intents") is None:
                raw["intents"] = []
                changed = True
            if raw.get("module_defaults") is None:
                raw["module_defaults"] = {"enabled_by_default": False, "admin_required_to_enable": False}
                changed = True
            if changed:
                _write_json(manifest_path, raw)
                return raw, True, "repaired"
            return raw, False, "ok"
        # unreadable/invalid -> replace with template and mark pending
        tmpl = build_template_manifest(module_id=module_id)
        _write_json(manifest_path, tmpl)
        return tmpl, True, "created"

    tmpl2 = build_template_manifest(module_id=module_id)
    _write_json(manifest_path, tmpl2)
    return tmpl2, True, "created"


def safe_auto_enable_decision(*, manifest: ModuleManifest, safe_caps: set[str], disallowed_caps: set[str]) -> Tuple[bool, str, bool]:
    """
    Returns: (auto_enable_ok, reason, requires_admin_to_enable)
    """
    all_caps: set[str] = set()
    for it in manifest.intents:
        all_caps |= set(it.required_capabilities or [])
        if it.resource_class.value != "light":
            return False, "resource_class not light", True
        if it.execution_mode.value == "job_process":
            return False, "execution_mode job_process requires admin", True

    if any(c in disallowed_caps for c in all_caps):
        return False, "disallowed capability present", True
    if not all_caps.issubset(set(safe_caps)):
        return False, "capability set not in safe allowlist", True
    return True, "safe auto-enable allowed", False


def registry_record_from_manifest(
    *,
    module_id: str,
    module_path: str,
    fingerprint: str,
    manifest_raw: Dict[str, Any],
    safe_caps: set[str],
    disallowed_caps: set[str],
) -> Dict[str, Any]:
    man, err = validate_manifest_dict(manifest_raw)
    pending_user_input = man is None
    contract_hash = contract_hash_from_manifest_dict(manifest_raw) if isinstance(manifest_raw, dict) else ""

    enabled = False
    safe_auto_enabled = False
    requires_admin = True
    reason = "installed disabled"
    enabled_at = None

    if man is not None:
        ok, why, req_admin = safe_auto_enable_decision(manifest=man, safe_caps=safe_caps, disallowed_caps=disallowed_caps)
        if ok:
            enabled = True
            safe_auto_enabled = True
            requires_admin = False
            reason = "auto_enabled_safe"
            enabled_at = _iso_now()
        else:
            enabled = False
            safe_auto_enabled = False
            requires_admin = bool(req_admin or man.module_defaults.admin_required_to_enable)
            reason = why

    return {
        "installed": True,
        "enabled": bool(enabled),
        "installed_at": _iso_now(),
        "enabled_at": enabled_at,
        "last_seen_fingerprint": str(fingerprint),
        "contract_hash": str(contract_hash),
        "module_path": str(module_path),
        "safe_auto_enabled": bool(safe_auto_enabled),
        "requires_admin_to_enable": bool(requires_admin),
        "reason": (f"manifest_invalid: {err}" if pending_user_input else str(reason))[:200],
        "missing_on_disk": False,
        "pending_user_input": bool(pending_user_input),
        "changed_requires_review": False,
    }

