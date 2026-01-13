from __future__ import annotations

"""
ModuleManager: discovery + wizard + enable/disable + audit wiring.

WHY THIS FILE EXISTS:
This is the single public API for module lifecycle operations. It ensures:
- discovery never imports module code
- modules are only runnable if installed+enabled
- all decisions are audit-logged via the existing event bus + audit timeline
"""

import importlib
import json
import os
import time
from typing import Any, Dict, Optional

from jarvis.core.events.models import BaseEvent, EventSeverity, SourceSubsystem
from jarvis.core.modules.discovery import ModuleDiscovery
from jarvis.core.modules.redaction import redact_module_payload
from jarvis.core.modules.wizard import (
    _iso_now,
    registry_record_from_manifest,
    repair_or_create_manifest,
    validate_manifest_dict,
)


SAFE_CAPS_DEFAULT = {"CAP_AUDIO_OUTPUT", "CAP_READ_FILES"}
DISALLOWED_CAPS = {
    "CAP_NETWORK_ACCESS",
    "CAP_RUN_SUBPROCESS",
    "CAP_HEAVY_COMPUTE",
    "CAP_DEVICE_CONTROL",
    "CAP_ADMIN_ACTION",
    "CAP_IMAGE_GENERATION",
    "CAP_CODE_GENERATION",
}


class ModuleManager:
    def __init__(
        self,
        *,
        config_manager: Any,
        modules_root: str,
        runtime_dir: str = "runtime",
        event_bus: Any = None,
        logger: Any = None,
        security_manager: Any = None,
    ):
        self.config = config_manager
        self.modules_root = str(modules_root)
        self.runtime_dir = str(runtime_dir)
        self.event_bus = event_bus
        self.logger = logger
        self.security = security_manager

    # ---- helpers ----
    def _emit(self, trace_id: str, event_type: str, payload: Dict[str, Any], *, severity: EventSeverity = EventSeverity.INFO) -> None:
        if self.event_bus is None:
            return
        try:
            self.event_bus.publish_nowait(
                BaseEvent(
                    event_type=event_type,
                    trace_id=trace_id,
                    source_subsystem=SourceSubsystem.modules,
                    severity=severity,
                    payload=redact_module_payload(payload),
                )
            )
        except Exception:
            pass

    def _load_modules_file_raw(self) -> Dict[str, Any]:
        raw = self.config.read_non_sensitive("modules.json") or {}
        if not isinstance(raw, dict):
            raw = {}
        raw.setdefault("schema_version", 1)
        raw.setdefault("intents", [])
        raw.setdefault("modules", {})
        # legacy: allow list
        if isinstance(raw.get("modules"), list):
            # best-effort upgrade to dict
            upgraded: Dict[str, Any] = {}
            for it in raw.get("modules") or []:
                if not isinstance(it, dict):
                    continue
                mid = it.get("module_id") or it.get("id") or it.get("module")
                if mid:
                    upgraded[str(mid)] = dict(it)
            raw["modules"] = upgraded
        if not isinstance(raw.get("modules"), dict):
            raw["modules"] = {}
        return raw

    def _save_modules_file_raw(self, raw: Dict[str, Any]) -> None:
        self.config.save_non_sensitive("modules.json", raw)

    def _save_inventory_snapshot(self, trace_id: str, snapshot: Dict[str, Any]) -> None:
        try:
            os.makedirs(self.runtime_dir, exist_ok=True)
            path = os.path.join(self.runtime_dir, "module_inventory.json")
            tmp = path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(snapshot, f, indent=2, ensure_ascii=False, sort_keys=True)
                f.write("\n")
            os.replace(tmp, path)
        except Exception:
            self._emit(trace_id, "module.inventory_write_failed", {"reason": "write_failed"}, severity=EventSeverity.WARN)

    def _sync_manifest_to_configs(self, *, module_id: str, manifest_raw: Dict[str, Any], trace_id: str) -> None:
        """
        Update capabilities.json intent_requirements and modules.json intents list
        to reflect the manifest contract. This does not enable execution by itself.
        """
        # Update modules.json intents list (routing + dispatch mapping)
        raw = self._load_modules_file_raw()
        intents = list(raw.get("intents") or [])
        by_id: Dict[str, Dict[str, Any]] = {str(i.get("id")): dict(i) for i in intents if isinstance(i, dict) and i.get("id")}
        for it in (manifest_raw.get("intents") or []):
            if not isinstance(it, dict):
                continue
            iid = str(it.get("intent_id") or "")
            if not iid:
                continue
            cur = by_id.get(iid) or {"id": iid}
            cur["id"] = iid
            cur["module_id"] = module_id
            cur.setdefault("keywords", [])
            cur.setdefault("required_args", [])
            by_id[iid] = cur
        raw["intents"] = list(by_id.values())
        self._save_modules_file_raw(raw)

        # Update capabilities.json intent_requirements
        caps_raw = self.config.read_non_sensitive("capabilities.json") or {}
        if not isinstance(caps_raw, dict):
            caps_raw = {}
        caps_raw.setdefault("intent_requirements", {})
        req_map = caps_raw.get("intent_requirements") or {}
        if not isinstance(req_map, dict):
            req_map = {}
        for it in (manifest_raw.get("intents") or []):
            if not isinstance(it, dict):
                continue
            iid = str(it.get("intent_id") or "")
            if not iid:
                continue
            caps = it.get("required_capabilities") or []
            if not isinstance(caps, list):
                caps = [caps]
            req_map[iid] = [str(c) for c in caps if str(c or "").strip()]
        caps_raw["intent_requirements"] = req_map
        # Validate before writing (capabilities loader is strict)
        from jarvis.core.capabilities.loader import validate_and_normalize

        _ = validate_and_normalize(caps_raw)
        self.config.save_non_sensitive("capabilities.json", caps_raw)
        self._emit(trace_id, "module.contract_synced", {"module_id": module_id})

    # ---- public API ----
    def list_registry(self) -> Dict[str, Any]:
        return self._load_modules_file_raw()

    def is_module_enabled(self, module_id: str) -> bool:
        raw = self._load_modules_file_raw()
        rec = (raw.get("modules") or {}).get(module_id) if isinstance(raw.get("modules"), dict) else None
        if not isinstance(rec, dict):
            return False
        return bool(rec.get("installed")) and bool(rec.get("enabled")) and not bool(rec.get("missing_on_disk"))

    def scan(self, *, trace_id: str = "modules") -> Dict[str, Any]:
        """
        Scan modules folder, reconcile registry, and write runtime inventory.
        Does not import module code.
        """
        self._emit(trace_id, "module.scan_started", {"action": "scan"})
        disc = ModuleDiscovery(modules_root=self.modules_root).scan()

        raw = self._load_modules_file_raw()
        registry: Dict[str, Any] = dict(raw.get("modules") or {})

        # Backwards compatibility: migrate legacy config/modules_registry.json entries
        # into the installed registry so they remain runnable only when explicitly enabled.
        try:
            legacy = self.config.read_non_sensitive("modules_registry.json") or {}
            legacy_entries = legacy.get("modules") or []
        except Exception:
            legacy_entries = []
        for e in legacy_entries or []:
            if not isinstance(e, dict):
                continue
            mod_path = str(e.get("module") or "")
            if not mod_path:
                continue
            legacy_id = mod_path.split(".")[-1]
            if not legacy_id:
                continue
            if legacy_id in registry:
                continue
            # Create a minimal installed record; contract is enforced elsewhere (dispatcher + capabilities).
            registry[legacy_id] = {
                "installed": True,
                "enabled": bool(e.get("enabled", False)),
                "installed_at": _iso_now(),
                "enabled_at": _iso_now() if bool(e.get("enabled", False)) else None,
                "last_seen_fingerprint": "",
                "contract_hash": "",
                "module_path": mod_path,
                "safe_auto_enabled": False,
                "requires_admin_to_enable": True,
                "reason": "legacy module_registry.json",
                "missing_on_disk": False,
                "pending_user_input": False,
                "changed_requires_review": False,
            }
            self._emit(trace_id, "module.installed", {"module_id": legacy_id, "module_path": mod_path})

        # detect removed
        for mid, rec in list(registry.items()):
            if not isinstance(rec, dict):
                continue
            # only folder-managed modules have a module_path under modules_root
            mpath = str(rec.get("module_path") or "")
            if mpath.startswith(self.modules_root) and mid not in disc:
                rec["missing_on_disk"] = True
                rec["enabled"] = False
                rec["enabled_at"] = None
                rec["reason"] = "missing on disk"
                self._emit(trace_id, "module.missing_on_disk", {"module_id": mid, "module_path": mpath})

        # reconcile discovered
        for mid, d in disc.items():
            if mid not in registry:
                self._emit(trace_id, "module.discovered_new", {"module_id": mid, "module_path": d.module_dir, "fingerprint": d.fingerprint})
                man_raw, wrote, status = repair_or_create_manifest(module_dir=d.module_dir, module_id=mid)
                if status in {"created", "repaired"}:
                    self._emit(trace_id, "module.manifest_repaired" if status == "repaired" else "module.manifest_created", {"module_id": mid})

                rec = registry_record_from_manifest(
                    module_id=mid,
                    module_path=d.module_dir.replace("\\", "/"),
                    fingerprint=d.fingerprint,
                    manifest_raw=man_raw,
                    safe_caps=set(SAFE_CAPS_DEFAULT),
                    disallowed_caps=set(DISALLOWED_CAPS),
                )
                registry[mid] = rec

                # If manifest is structurally valid, sync intents/capability mappings.
                man, _err = validate_manifest_dict(man_raw if isinstance(man_raw, dict) else {})
                if man is not None:
                    try:
                        self._sync_manifest_to_configs(module_id=mid, manifest_raw=man_raw, trace_id=trace_id)
                    except Exception as e:
                        # Fail-safe: keep module disabled and mark pending.
                        rec["enabled"] = False
                        rec["pending_user_input"] = True
                        rec["requires_admin_to_enable"] = True
                        rec["reason"] = f"manifest/capabilities sync failed: {str(e)[:120]}"
                        registry[mid] = rec
                        self._emit(trace_id, "module.manifest_invalid", {"module_id": mid, "reason": str(e)[:200]}, severity=EventSeverity.WARN)

                if bool(rec.get("enabled")) and bool(rec.get("safe_auto_enabled")):
                    self._emit(trace_id, "module.auto_enabled_safe", {"module_id": mid, "fingerprint": d.fingerprint, "reason": rec.get("reason")})
                else:
                    self._emit(trace_id, "module.installed_disabled_requires_admin", {"module_id": mid, "fingerprint": d.fingerprint, "reason": rec.get("reason")})
                continue

            # existing module: detect changes
            rec2 = registry.get(mid)
            if not isinstance(rec2, dict):
                rec2 = {}
            prev_fp = str(rec2.get("last_seen_fingerprint") or "")
            prev_contract = str(rec2.get("contract_hash") or "")
            if prev_fp and prev_fp != d.fingerprint:
                # contract change => disable + require review
                if d.contract_hash and prev_contract and d.contract_hash != prev_contract:
                    rec2["enabled"] = False
                    rec2["enabled_at"] = None
                    rec2["changed_requires_review"] = True
                    rec2["reason"] = "contract changed; requires review"
                    self._emit(trace_id, "module.changed_requires_review", {"module_id": mid, "fingerprint": d.fingerprint})
                rec2["last_seen_fingerprint"] = d.fingerprint
                if d.contract_hash:
                    rec2["contract_hash"] = d.contract_hash
                rec2["missing_on_disk"] = False
                registry[mid] = rec2
            else:
                # refresh seen flags
                rec2["last_seen_fingerprint"] = d.fingerprint
                if d.contract_hash:
                    rec2["contract_hash"] = d.contract_hash
                rec2["missing_on_disk"] = False
                registry[mid] = rec2

        raw["modules"] = registry
        self._save_modules_file_raw(raw)

        snapshot = {
            "scanned_at": _iso_now(),
            "modules_root": self.modules_root.replace("\\", "/"),
            "found": sorted(list(disc.keys())),
            "registry_count": len(registry),
        }
        self._save_inventory_snapshot(trace_id, snapshot)
        self._emit(trace_id, "module.scan_completed", {"action": "scan", "count": len(disc)})
        return {"ok": True, "found": sorted(list(disc.keys())), "registry": raw.get("modules")}

    def enable(self, module_id: str, *, trace_id: str = "modules") -> bool:
        raw = self._load_modules_file_raw()
        reg: Dict[str, Any] = dict(raw.get("modules") or {})
        rec = reg.get(module_id)
        if not isinstance(rec, dict) or not bool(rec.get("installed")):
            self._emit(trace_id, "module.enable_denied", {"module_id": module_id, "reason": "not installed"}, severity=EventSeverity.WARN)
            return False
        if bool(rec.get("missing_on_disk")):
            self._emit(trace_id, "module.enable_denied", {"module_id": module_id, "reason": "missing on disk"}, severity=EventSeverity.WARN)
            return False
        # admin gate if required
        if bool(rec.get("requires_admin_to_enable")):
            if self.security is None or not bool(getattr(self.security, "is_admin", lambda: False)()):
                self._emit(trace_id, "module.enable_denied", {"module_id": module_id, "reason": "admin required"}, severity=EventSeverity.WARN)
                return False

        # validate manifest before enabling
        mdir = str(rec.get("module_path") or "")
        mpath = os.path.join(mdir, "module.json")
        try:
            with open(mpath, "r", encoding="utf-8") as f:
                man_raw = json.load(f)
        except Exception:
            man_raw = None
        if not isinstance(man_raw, dict):
            self._emit(trace_id, "module.enable_denied", {"module_id": module_id, "reason": "manifest missing/invalid"}, severity=EventSeverity.WARN)
            return False
        man, err = validate_manifest_dict(man_raw)
        if man is None:
            self._emit(trace_id, "module.enable_denied", {"module_id": module_id, "reason": f"manifest invalid: {err}"}, severity=EventSeverity.WARN)
            return False

        rec["enabled"] = True
        rec["enabled_at"] = _iso_now()
        rec["reason"] = "enabled"
        rec["pending_user_input"] = False
        rec["changed_requires_review"] = False
        reg[module_id] = rec
        raw["modules"] = reg
        self._save_modules_file_raw(raw)
        self._emit(trace_id, "module.enabled", {"module_id": module_id})
        return True

    def disable(self, module_id: str, *, trace_id: str = "modules") -> bool:
        raw = self._load_modules_file_raw()
        reg: Dict[str, Any] = dict(raw.get("modules") or {})
        rec = reg.get(module_id)
        if not isinstance(rec, dict) or not bool(rec.get("installed")):
            return False
        # admin gate is not strictly required to disable, but keep consistent for safety if required
        if self.security is not None and bool(rec.get("requires_admin_to_enable")):
            if not bool(getattr(self.security, "is_admin", lambda: False)()):
                self._emit(trace_id, "module.disable_denied", {"module_id": module_id, "reason": "admin required"}, severity=EventSeverity.WARN)
                return False
        rec["enabled"] = False
        rec["enabled_at"] = None
        rec["reason"] = "disabled"
        reg[module_id] = rec
        raw["modules"] = reg
        self._save_modules_file_raw(raw)
        self._emit(trace_id, "module.disabled", {"module_id": module_id})
        return True

    def export(self, path: str) -> str:
        """
        Export sanitized registry (no secrets, no file contents).
        """
        raw = self._load_modules_file_raw()
        out = {"schema_version": int(raw.get("schema_version") or 1), "modules": raw.get("modules") or {}, "intents_count": len(raw.get("intents") or [])}
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(out, f, indent=2, ensure_ascii=False, sort_keys=True)
            f.write("\n")
        return path

    def load_enabled_entrypoint(self, module_id: str) -> Optional[Any]:
        """
        Import and resolve entrypoint for an enabled module.
        This is ONLY used after install+enable gating passes.
        """
        raw = self._load_modules_file_raw()
        rec = (raw.get("modules") or {}).get(module_id) if isinstance(raw.get("modules"), dict) else None
        if not isinstance(rec, dict) or not bool(rec.get("enabled")):
            return None
        mdir = str(rec.get("module_path") or "")
        mpath = os.path.join(mdir, "module.json")
        try:
            with open(mpath, "r", encoding="utf-8") as f:
                man_raw = json.load(f)
        except Exception:
            return None
        if not isinstance(man_raw, dict):
            return None
        man, _err = validate_manifest_dict(man_raw)
        if man is None:
            return None
        ep = str(man.entrypoint or "")
        if ":" not in ep:
            return None
        mod, fn = ep.split(":", 1)
        m = importlib.import_module(mod)
        return getattr(m, fn, None)

