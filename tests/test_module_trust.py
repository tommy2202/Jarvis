from __future__ import annotations

import json
import os

from jarvis.core.config.manager import ConfigManager
from jarvis.core.config.paths import ConfigFsPaths
from jarvis.core.modules.manager import ModuleManager
from jarvis.core.security import AdminSession, SecurityManager
from jarvis.core.secure_store import SecureStore


class _L:
    def info(self, *_a, **_k): ...
    def warning(self, *_a, **_k): ...
    def error(self, *_a, **_k): ...


class _Bus:
    def __init__(self) -> None:
        self.events: list[object] = []

    def publish_nowait(self, ev) -> None:  # noqa: ANN001
        self.events.append(ev)


def _make_cfg(tmp_path) -> ConfigManager:
    cm = ConfigManager(fs=ConfigFsPaths(str(tmp_path)), logger=_L(), read_only=False)
    cm.load_all()
    return cm


def _write_module_json(mod_dir: str, obj: dict) -> None:
    os.makedirs(mod_dir, exist_ok=True)
    path = os.path.join(mod_dir, "module.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2, ensure_ascii=False)
        f.write("\n")


def test_untrusted_module_blocked(tmp_path):
    cm = _make_cfg(tmp_path)
    modules_root = tmp_path / "jarvis" / "modules"
    mod_dir = modules_root / "safe.three"
    _write_module_json(
        str(mod_dir),
        {
            "schema_version": 1,
            "module_id": "safe.three",
            "version": "0.1.0",
            "display_name": "Safe",
            "description": "",
            "entrypoint": "safe_three:register",
            "intents": [],
            "module_defaults": {"enabled_by_default": False, "admin_required_to_enable": False},
        },
    )

    # Pre-seed registry to simulate a non-local provenance install.
    cm.save_non_sensitive(
        "modules.json",
        {
            "schema_version": 1,
            "intents": [],
            "modules": {
                "safe.three": {
                    "installed": True,
                    "enabled": True,
                    "installed_at": "t",
                    "enabled_at": "t",
                    "module_path": str(mod_dir).replace("\\", "/"),
                    "provenance": "git",
                    "trusted": False,
                    "requires_admin_to_enable": False,
                    "safe_auto_enabled": False,
                    "missing_on_disk": False,
                    "pending_user_input": False,
                    "changed_requires_review": False,
                }
            },
        },
    )

    mm = ModuleManager(config_manager=cm, modules_root=str(modules_root), runtime_dir=str(tmp_path / "runtime"), event_bus=None, logger=_L(), security_manager=None)
    _ = mm.scan(trace_id="t")
    reg = mm.list_registry().get("modules") or {}
    assert bool(reg["safe.three"]["enabled"]) is False
    assert mm.is_module_enabled("safe.three") is False


def test_admin_can_trust_module(tmp_path):
    cm = _make_cfg(tmp_path)
    modules_root = tmp_path / "jarvis" / "modules"
    mod_dir = modules_root / "safe.three"
    _write_module_json(
        str(mod_dir),
        {
            "schema_version": 1,
            "module_id": "safe.three",
            "version": "0.1.0",
            "display_name": "Safe",
            "description": "",
            "entrypoint": "safe_three:register",
            "intents": [],
            "module_defaults": {"enabled_by_default": False, "admin_required_to_enable": False},
        },
    )

    cm.save_non_sensitive(
        "modules.json",
        {
            "schema_version": 1,
            "intents": [],
            "modules": {
                "safe.three": {
                    "installed": True,
                    "enabled": False,
                    "installed_at": "t",
                    "enabled_at": None,
                    "module_path": str(mod_dir).replace("\\", "/"),
                    "provenance": "git",
                    "trusted": False,
                    "requires_admin_to_enable": False,
                    "safe_auto_enabled": False,
                    "missing_on_disk": False,
                    "pending_user_input": False,
                    "changed_requires_review": False,
                }
            },
        },
    )

    store = SecureStore(usb_key_path=str(tmp_path / "usb_missing.bin"), store_path=str(tmp_path / "store.enc"))
    sec = SecurityManager(secure_store=store, admin_session=AdminSession(timeout_seconds=9999))
    mm = ModuleManager(config_manager=cm, modules_root=str(modules_root), runtime_dir=str(tmp_path / "runtime"), event_bus=None, logger=_L(), security_manager=sec)
    _ = mm.scan(trace_id="t")

    sec.admin_session.unlock()
    assert mm.set_module_trusted("safe.three", trusted=True, trace_id="t") is True
    assert mm.enable("safe.three", trace_id="t") is True
    assert mm.is_module_enabled("safe.three") is True


def test_dev_mode_override_logged(tmp_path):
    cm = _make_cfg(tmp_path)
    cm.save_non_sensitive("module_trust.json", {"allow_unsigned_modules": False, "dev_mode_override": True})
    modules_root = tmp_path / "jarvis" / "modules"
    mod_dir = modules_root / "safe.three"
    _write_module_json(
        str(mod_dir),
        {
            "schema_version": 1,
            "module_id": "safe.three",
            "version": "0.1.0",
            "display_name": "Safe",
            "description": "",
            "entrypoint": "safe_three:register",
            "intents": [],
            "module_defaults": {"enabled_by_default": False, "admin_required_to_enable": False},
        },
    )

    cm.save_non_sensitive(
        "modules.json",
        {
            "schema_version": 1,
            "intents": [],
            "modules": {
                "safe.three": {
                    "installed": True,
                    "enabled": True,
                    "installed_at": "t",
                    "enabled_at": "t",
                    "module_path": str(mod_dir).replace("\\", "/"),
                    "provenance": "git",
                    "trusted": False,
                    "requires_admin_to_enable": False,
                    "safe_auto_enabled": False,
                    "missing_on_disk": False,
                    "pending_user_input": False,
                    "changed_requires_review": False,
                }
            },
        },
    )

    bus = _Bus()
    mm = ModuleManager(config_manager=cm, modules_root=str(modules_root), runtime_dir=str(tmp_path / "runtime"), event_bus=bus, logger=_L(), security_manager=None)
    _ = mm.scan(trace_id="t")

    assert mm.is_module_enabled("safe.three") is True
    assert any(getattr(ev, "event_type", "") == "module.trust_dev_override_logged" for ev in bus.events)

