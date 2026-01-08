from __future__ import annotations

import importlib
import os
import sys
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional, Tuple

from jarvis.core.config_loader import ConfigLoader, ConfigPaths
from jarvis.core.crypto import SecureStoreLockedError


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
        if not name.endswith(".py"):
            continue
        if name.startswith("__"):
            continue
        mod_name = name[:-3]
        out.append(f"jarvis.modules.{mod_name}")
    return sorted(set(out))


def _load_module_meta(module_path: str) -> Optional[Dict[str, Any]]:
    try:
        m = importlib.import_module(module_path)
        meta = getattr(m, "MODULE_META", None)
        return meta if isinstance(meta, dict) else None
    except Exception:  # noqa: BLE001
        return None


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

    def detect(self) -> Dict[str, Any]:
        registry = self.cfg.load(self.paths.modules_registry) or {}
        reg_entries = registry.get("modules") or []
        reg_paths = {e.get("module") for e in reg_entries if isinstance(e, dict)}

        disk = _scan_modules_dir(os.path.join("jarvis", "modules"))
        missing_in_registry = [m for m in disk if m not in reg_paths]

        modules_cfg = self.cfg.load(self.paths.modules) or {}
        intents_cfg = {i.get("id"): i for i in (modules_cfg.get("intents") or []) if isinstance(i, dict) and i.get("id")}

        perms_cfg = self.cfg.load(self.paths.permissions) or {}
        perms_intents = perms_cfg.get("intents") or {}

        resp_cfg = self.cfg.load(self.paths.responses) or {}
        templates = resp_cfg.get("confirmations") or {}

        needs_setup: List[Dict[str, Any]] = []
        for e in reg_entries:
            if not isinstance(e, dict) or not e.get("enabled"):
                continue
            module_path = str(e.get("module"))
            meta = _load_module_meta(module_path) or {}
            module_id = str(meta.get("id", module_path))
            # Assume one intent by default: <module_id>.run if none exists.
            default_intent_id = str(meta.get("default_intent") or f"{module_id}.run")
            if default_intent_id not in intents_cfg or default_intent_id not in perms_intents or default_intent_id not in templates:
                needs_setup.append({"module": module_path, "module_id": module_id, "intent_id": default_intent_id, "meta": meta})

        return {"missing_in_registry": missing_in_registry, "needs_setup": needs_setup}

    def run_interactive(self) -> None:
        if not _has_stdin():
            self.logger.warning("Setup wizard skipped (no interactive stdin).")
            return
        self._run(input)

    def _run(self, input_fn: InputFn) -> None:
        detection = self.detect()
        missing = detection["missing_in_registry"]
        needs_setup = detection["needs_setup"]

        if not missing and not needs_setup:
            return

        registry = self.cfg.load(self.paths.modules_registry) or {"modules": []}
        reg_entries = registry.get("modules") or []

        for module_path in missing:
            meta = _load_module_meta(module_path) or {}
            name = meta.get("name") or module_path
            if _yes_no(f"New module detected: {name}. Add to registry (disabled by default)?", input_fn, default_yes=True):
                reg_entries.append({"module": module_path, "enabled": False})

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

