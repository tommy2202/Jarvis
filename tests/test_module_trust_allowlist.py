from __future__ import annotations

from jarvis.core.modules.manager import ModuleManager
from jarvis.core.security import AdminSession, SecurityManager
from jarvis.core.secure_store import SecureStore
from tests.helpers.module_trust import DummyLogger, EventBusCapture, make_cfg, write_module_json


def test_allowlist_blocks_non_allowlisted_module(tmp_path):
    cm = make_cfg(tmp_path)
    cm.save_non_sensitive("module_trust.json", {"trusted_module_ids": ["safe.allowlisted"], "dev_mode": False})
    modules_root = tmp_path / "jarvis" / "modules"
    mod_dir = modules_root / "demo.blocked"
    write_module_json(
        str(mod_dir),
        {
            "schema_version": 1,
            "module_id": "demo.blocked",
            "version": "0.1.0",
            "display_name": "Blocked",
            "description": "",
            "entrypoint": "demo_blocked:register",
            "intents": [
                {
                    "intent_id": "demo.blocked.ping",
                    "description": "",
                    "args_schema": {},
                    "required_capabilities": ["CAP_AUDIO_OUTPUT"],
                    "resource_class": "light",
                    "execution_mode": "inline",
                }
            ],
            "module_defaults": {"enabled_by_default": False, "admin_required_to_enable": False},
        },
    )

    mm = ModuleManager(config_manager=cm, modules_root=str(modules_root), runtime_dir=str(tmp_path / "runtime"), event_bus=None, logger=DummyLogger(), security_manager=None)
    _ = mm.scan(trace_id="t")
    reg = mm.list_registry().get("modules") or {}
    assert bool(reg["demo.blocked"]["enabled"]) is False
    assert str(reg["demo.blocked"].get("reason") or "").startswith("not in trusted allowlist")
    assert mm.is_module_enabled("demo.blocked") is False


def test_allowlisted_module_requires_admin_when_not_safe(tmp_path):
    cm = make_cfg(tmp_path)
    cm.save_non_sensitive("module_trust.json", {"trusted_module_ids": ["demo.risky"], "dev_mode": False})
    modules_root = tmp_path / "jarvis" / "modules"
    mod_dir = modules_root / "demo.risky"
    write_module_json(
        str(mod_dir),
        {
            "schema_version": 1,
            "module_id": "demo.risky",
            "version": "0.1.0",
            "display_name": "Risky",
            "description": "",
            "entrypoint": "demo_risky:register",
            "intents": [
                {
                    "intent_id": "demo.risky.run",
                    "description": "",
                    "args_schema": {},
                    "required_capabilities": ["CAP_RUN_SUBPROCESS"],
                    "resource_class": "light",
                    "execution_mode": "inline",
                }
            ],
            "module_defaults": {"enabled_by_default": False, "admin_required_to_enable": False},
        },
    )

    store = SecureStore(usb_key_path=str(tmp_path / "usb_missing.bin"), store_path=str(tmp_path / "store.enc"))
    sec = SecurityManager(secure_store=store, admin_session=AdminSession(timeout_seconds=9999))
    mm = ModuleManager(config_manager=cm, modules_root=str(modules_root), runtime_dir=str(tmp_path / "runtime"), event_bus=None, logger=DummyLogger(), security_manager=sec)
    _ = mm.scan(trace_id="t")
    reg = mm.list_registry().get("modules") or {}
    assert bool(reg["demo.risky"]["enabled"]) is False
    assert bool(reg["demo.risky"].get("requires_admin_to_enable")) is True

    assert mm.enable("demo.risky", trace_id="t") is False
    sec.admin_session.unlock()
    assert mm.enable("demo.risky", trace_id="t") is True
    assert mm.is_module_enabled("demo.risky") is True


def test_dev_mode_allowlist_override_audited(tmp_path):
    cm = make_cfg(tmp_path)
    cm.save_non_sensitive("module_trust.json", {"trusted_module_ids": ["only.this"], "dev_mode": True})
    modules_root = tmp_path / "jarvis" / "modules"
    mod_dir = modules_root / "demo.override"
    write_module_json(
        str(mod_dir),
        {
            "schema_version": 1,
            "module_id": "demo.override",
            "version": "0.1.0",
            "display_name": "Override",
            "description": "",
            "entrypoint": "demo_override:register",
            "intents": [
                {
                    "intent_id": "demo.override.ping",
                    "description": "",
                    "args_schema": {},
                    "required_capabilities": [],
                    "resource_class": "light",
                    "execution_mode": "inline",
                }
            ],
            "module_defaults": {"enabled_by_default": False, "admin_required_to_enable": False},
        },
    )

    store = SecureStore(usb_key_path=str(tmp_path / "usb_missing.bin"), store_path=str(tmp_path / "store.enc"))
    sec = SecurityManager(secure_store=store, admin_session=AdminSession(timeout_seconds=9999))
    sec.admin_session.unlock()
    bus = EventBusCapture()
    mm = ModuleManager(config_manager=cm, modules_root=str(modules_root), runtime_dir=str(tmp_path / "runtime"), event_bus=bus, logger=DummyLogger(), security_manager=sec)
    _ = mm.scan(trace_id="t")

    assert mm.enable("demo.override", trace_id="t") is True
    assert any(getattr(ev, "event_type", "") == "module.dev_mode_allowlist_override" for ev in bus.events)
