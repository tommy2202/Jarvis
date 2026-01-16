from __future__ import annotations

import ast
import json
import os
import sys
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional, Tuple

from jarvis.core.config_loader import ConfigLoader, ConfigPaths
from jarvis.core.crypto import SecureStoreLockedError
from jarvis.core.events.models import BaseEvent, EventSeverity, SourceSubsystem
from jarvis.core.modules.redaction import redact_module_payload


InputFn = Callable[[str], str]


def _has_stdin() -> bool:
    try:
        return sys.stdin is not None and sys.stdin.isatty()
    except Exception:  # noqa: BLE001
        return False


def _scan_modules_dir(modules_dir: str) -> List[str]:
    out: List[str] = []
    if not os.path.isdir(modules_dir):
        return out
    for name in os.listdir(modules_dir):
        if name.startswith("__"):
            continue
        path = os.path.join(modules_dir, name)
        if os.path.isdir(path):
            init_path = os.path.join(path, "__init__.py")
            if os.path.isfile(init_path):
                out.append(f"jarvis.modules.{name}")
            continue
        if not name.endswith(".py"):
            continue
        mod_name = name[:-3]
        out.append(f"jarvis.modules.{mod_name}")
    return sorted(set(out))


def _module_id_from_path(module_path: str) -> str:
    parts = [p for p in str(module_path or "").split(".") if p]
    return parts[-1] if parts else str(module_path or "")


def _module_dir_for_id(module_id: str) -> str:
    return os.path.join("jarvis", "modules", module_id)


def _module_source_path(module_id: str) -> Optional[str]:
    py_path = os.path.join("jarvis", "modules", f"{module_id}.py")
    if os.path.isfile(py_path):
        return py_path
    pkg_init = os.path.join("jarvis", "modules", module_id, "__init__.py")
    if os.path.isfile(pkg_init):
        return pkg_init
    return None


def _manifest_to_meta(raw: Dict[str, Any]) -> Dict[str, Any]:
    module_id = str(raw.get("module_id") or "").strip()
    display_name = str(raw.get("display_name") or module_id)
    description = str(raw.get("description") or "")
    intents = raw.get("intents") if isinstance(raw.get("intents"), list) else []

    meta: Dict[str, Any] = {
        "id": module_id,
        "name": display_name,
        "description": description,
        "required_args": [],
    }

    intent_ids: List[str] = []
    caps: set[str] = set()
    resource_intensive = False
    for it in intents:
        if not isinstance(it, dict):
            continue
        iid = str(it.get("intent_id") or "").strip()
        if iid:
            intent_ids.append(iid)
        rc = str(it.get("resource_class") or "").strip().lower()
        exec_mode = str(it.get("execution_mode") or "").strip().lower()
        if rc in {"medium", "heavy"} or exec_mode == "job_process":
            resource_intensive = True
        req_caps = it.get("required_capabilities")
        if isinstance(req_caps, list):
            for c in req_caps:
                cs = str(c or "").strip()
                if cs:
                    caps.add(cs)
        elif isinstance(req_caps, str) and req_caps.strip():
            caps.add(req_caps.strip())

    if len(intent_ids) == 1:
        meta["default_intent"] = intent_ids[0]
    if intent_ids:
        meta["intent_ids"] = intent_ids
    if caps:
        meta["required_capabilities"] = sorted(caps)
    meta["resource_intensive"] = bool(resource_intensive)

    return meta


def _read_manifest_meta(module_id: str) -> Tuple[Optional[Dict[str, Any]], bool, str]:
    manifest_path = os.path.join(_module_dir_for_id(module_id), "module.json")
    if not os.path.isfile(manifest_path):
        return None, False, ""
    try:
        with open(manifest_path, "r", encoding="utf-8") as f:
            raw = json.load(f)
    except Exception as e:  # noqa: BLE001
        return None, True, f"manifest_read_failed: {e}"
    if not isinstance(raw, dict):
        return None, True, "manifest_invalid"
    man_id = str(raw.get("module_id") or "").strip()
    if not man_id:
        return None, True, "manifest_missing_module_id"
    if man_id != module_id:
        return None, True, "manifest_module_id_mismatch"
    return _manifest_to_meta(raw), True, ""


def _literal_dict_from_node(node: ast.AST) -> Optional[Dict[str, Any]]:
    if not isinstance(node, ast.Dict):
        return None
    try:
        val = ast.literal_eval(node)
    except Exception:  # noqa: BLE001
        return None
    return val if isinstance(val, dict) else None


def _read_module_meta_from_source(source_path: str) -> Optional[Dict[str, Any]]:
    try:
        with open(source_path, "r", encoding="utf-8") as f:
            src = f.read()
    except Exception:  # noqa: BLE001
        return None
    try:
        tree = ast.parse(src, filename=source_path)
    except Exception:  # noqa: BLE001
        return None
    for node in tree.body:
        if isinstance(node, ast.Assign):
            if any(isinstance(t, ast.Name) and t.id == "MODULE_META" for t in node.targets):
                return _literal_dict_from_node(node.value)
        if isinstance(node, ast.AnnAssign):
            if isinstance(node.target, ast.Name) and node.target.id == "MODULE_META":
                return _literal_dict_from_node(node.value)
    return None


def _load_module_meta(module_path: str) -> Tuple[Optional[Dict[str, Any]], str, str]:
    module_id = _module_id_from_path(module_path)
    meta, has_manifest, err = _read_manifest_meta(module_id)
    if has_manifest:
        if meta is not None:
            return meta, "manifest", ""
        return None, "manifest", err or "manifest_invalid"
    source_path = _module_source_path(module_id)
    if not source_path:
        return None, "source", "source_missing"
    meta2 = _read_module_meta_from_source(source_path)
    if meta2 is None:
        return None, "ast", "ast_literal_extract_failed"
    return meta2, "ast", ""


def _yes_no(prompt: str, input_fn: InputFn, default_yes: bool = True) -> bool:
    suffix = " [Y/n] " if default_yes else " [y/N] "
    resp = (input_fn(prompt + suffix) or "").strip().lower()
    if resp == "":
        return default_yes
    return resp in {"y", "yes"}


def _csv(prompt: str, input_fn: InputFn) -> List[str]:
    resp = (input_fn(prompt + " (comma-separated) ") or "").strip()
    if not resp:
        return []
    return [x.strip() for x in resp.split(",") if x.strip()]


@dataclass
class SetupWizard:
    cfg: ConfigLoader
    paths: ConfigPaths
    secure_store: Any  # SecureStore (avoid circular typing noise)
    logger: Any
    event_bus: Any = None

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

    def detect(self) -> Dict[str, Any]:
        registry = self.cfg.load(self.paths.modules_registry) or {}
        reg_entries = registry.get("modules") or []
        reg_paths = {e.get("module") for e in reg_entries if isinstance(e, dict)}

        disk = _scan_modules_dir(os.path.join("jarvis", "modules"))
        meta_cache: Dict[str, Tuple[Optional[Dict[str, Any]], str, str]] = {}

        def _get_meta(module_path: str) -> Tuple[Dict[str, Any], str, str, bool]:
            if module_path not in meta_cache:
                meta, source, err = _load_module_meta(module_path)
                meta_cache[module_path] = (meta, source, err)
                if meta is None and err:
                    module_id = _module_id_from_path(module_path)
                    self._emit(
                        "setup_wizard",
                        "module.legacy_metadata_extract_failed",
                        {"module_id": module_id, "module_path": module_path, "reason": err},
                        severity=EventSeverity.WARN,
                    )
            meta2, source2, err2 = meta_cache[module_path]
            return (meta2 or {}), source2, err2, meta2 is None

        modules_cfg = self.cfg.load(self.paths.modules) or {}
        intents_cfg = {i.get("id"): i for i in (modules_cfg.get("intents") or []) if isinstance(i, dict) and i.get("id")}

        perms_cfg = self.cfg.load(self.paths.permissions) or {}
        perms_intents = perms_cfg.get("intents") or {}

        resp_cfg = self.cfg.load(self.paths.responses) or {}
        templates = resp_cfg.get("confirmations") or {}

        missing_entries: List[Dict[str, Any]] = []
        for module_path in disk:
            if module_path in reg_paths:
                continue
            meta, source, err, missing = _get_meta(module_path)
            module_id = str(meta.get("id") or _module_id_from_path(module_path))
            self._emit(
                "setup_wizard",
                "module.legacy_discovered_new",
                {"module_id": module_id, "module_path": module_path, "action": "detected"},
            )
            missing_entries.append(
                {
                    "module": module_path,
                    "module_id": module_id,
                    "meta": meta,
                    "meta_status": "unknown" if missing else "ok",
                    "meta_source": source,
                    "pending_review": True,
                    "meta_error": err or "",
                }
            )

        needs_setup: List[Dict[str, Any]] = []
        for e in reg_entries:
            if not isinstance(e, dict) or not e.get("enabled"):
                continue
            module_path = str(e.get("module"))
            meta, source, err, missing = _get_meta(module_path)
            module_id = str(meta.get("id") or module_path)
            # Assume one intent by default: <module_id>.run if none exists.
            default_intent_id = str(meta.get("default_intent") or f"{module_id}.run")
            if default_intent_id not in intents_cfg or default_intent_id not in perms_intents or default_intent_id not in templates:
                needs_setup.append(
                    {
                        "module": module_path,
                        "module_id": module_id,
                        "intent_id": default_intent_id,
                        "meta": meta,
                        "meta_status": "unknown" if missing else "ok",
                        "meta_source": source,
                        "meta_error": err or "",
                    }
                )

        missing_in_registry = [m.get("module") for m in missing_entries]
        return {"missing_in_registry": missing_in_registry, "missing_modules": missing_entries, "needs_setup": needs_setup}

    def run_interactive(self) -> None:
        if not _has_stdin():
            self.logger.warning("Setup wizard skipped (no interactive stdin).")
            return
        self._run(input)

    def _run(self, input_fn: InputFn) -> None:
        detection = self.detect()
        missing_entries = detection.get("missing_modules") or []
        needs_setup = detection["needs_setup"]

        if not missing_entries and not needs_setup:
            return

        registry = self.cfg.load(self.paths.modules_registry) or {"modules": []}
        reg_entries = registry.get("modules") or []

        for item in missing_entries:
            module_path = str(item.get("module") or "")
            meta = item.get("meta") or {}
            module_id = str(item.get("module_id") or _module_id_from_path(module_path))
            name = meta.get("name") or module_path
            if _yes_no(f"New module detected: {name}. Add to registry (disabled by default)?", input_fn, default_yes=True):
                reg_entries.append({"module": module_path, "enabled": False})
                self._emit(
                    "setup_wizard",
                    "module.legacy_pending_review",
                    {"module_id": module_id, "module_path": module_path, "enabled": False, "reason": "pending_review_disabled"},
                )

        registry["modules"] = reg_entries
        self.cfg.save(self.paths.modules_registry, registry)

        # Reload needs setup now that registry may have changed.
        detection = self.detect()
        needs_setup = detection["needs_setup"]
        for item in needs_setup:
            module_path = item["module"]
            module_id = item["module_id"]
            intent_id = item["intent_id"]
            meta = item.get("meta") or {}

            if not _yes_no(f"Module needs setup: {module_path}. Run setup now?", input_fn, default_yes=True):
                continue

            # Safe defaults
            declared_resource_intensive = bool(meta.get("resource_intensive", False))

            admin_only = _yes_no("Is this module admin-only?", input_fn, default_yes=declared_resource_intensive)
            resource_intensive = _yes_no("Is this module resource-intensive?", input_fn, default_yes=declared_resource_intensive)
            if resource_intensive:
                admin_only = True  # fail-safe
            network_access = _yes_no("Does this module need network access?", input_fn, default_yes=False)
            keywords = _csv("Enter intent keywords for routing", input_fn)
            template = (input_fn("Confirmation template (use {arg} placeholders), blank for default: ") or "").strip()
            if not template:
                template = f"Okay — running {module_id}."

            # Write non-sensitive configs
            modules_cfg = self.cfg.load(self.paths.modules) or {}
            intents = modules_cfg.get("intents") or []
            if not any(isinstance(i, dict) and i.get("id") == intent_id for i in intents):
                intents.append(
                    {
                        "id": intent_id,
                        "module_id": module_id,
                        "keywords": keywords,
                        "required_args": list(meta.get("required_args") or []),
                    }
                )
            modules_cfg["intents"] = intents
            self.cfg.save(self.paths.modules, modules_cfg)

            perms_cfg = self.cfg.load(self.paths.permissions) or {}
            perms_cfg.setdefault("intents", {})
            perms_cfg["intents"][intent_id] = {
                "requires_admin": bool(admin_only),
                "resource_intensive": bool(resource_intensive),
                "network_access": bool(network_access),
            }
            self.cfg.save(self.paths.permissions, perms_cfg)

            resp_cfg = self.cfg.load(self.paths.responses) or {}
            resp_cfg.setdefault("confirmations", {})
            resp_cfg["confirmations"][intent_id] = template
            self.cfg.save(self.paths.responses, resp_cfg)

            # Secrets (if module declares any)
            secrets_decl = meta.get("secrets") or []
            for s in secrets_decl:
                if not isinstance(s, dict) or not s.get("key"):
                    continue
                skey = f"modules.{module_id}.{s['key']}"
                prompt = str(s.get("prompt") or f"Enter secret for {s['key']}: ")
                val = (input_fn(prompt) or "").strip()
                if not val:
                    continue
                try:
                    self.secure_store.secure_set(skey, val)
                except SecureStoreLockedError:
                    self.logger.warning("USB key missing: cannot write secrets to secure store; keeping module disabled.")
                    self._disable_module_in_registry(module_path)
                    break

    def _disable_module_in_registry(self, module_path: str) -> None:
        registry = self.cfg.load(self.paths.modules_registry) or {"modules": []}
        changed = False
        for e in registry.get("modules") or []:
            if isinstance(e, dict) and e.get("module") == module_path:
                if e.get("enabled") is True:
                    e["enabled"] = False
                    changed = True
        if changed:
            self.cfg.save(self.paths.modules_registry, registry)

