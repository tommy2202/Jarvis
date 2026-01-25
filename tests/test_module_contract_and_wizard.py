from __future__ import annotations

"""
Module contract + setup wizard enforcement tests.

WHY THIS FILE EXISTS:
These tests lock the security invariants around module discovery (no imports),
install/repair (manifest + registry), safe auto-enable rules, admin-gated enable,
dispatcher gating, and change detection requiring review.
"""

import importlib
import json
import os

from jarvis.core.capabilities.audit import CapabilityAuditLogger
from jarvis.core.capabilities.engine import CapabilityEngine
from jarvis.core.capabilities.loader import validate_and_normalize
from jarvis.core.config.manager import ConfigManager
from jarvis.core.config.paths import ConfigFsPaths
from jarvis.core.dispatcher import Dispatcher
from jarvis.core.events import EventLogger
from jarvis.core.module_registry import ModuleRegistry
from jarvis.core.modules.manager import ModuleManager
from jarvis.core.security import AdminSession, PermissionPolicy, SecurityManager
from jarvis.core.secure_store import SecureStore


class _L:
    def info(self, *_a, **_k): ...
    def warning(self, *_a, **_k): ...
    def error(self, *_a, **_k): ...


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


def test_discovery_detects_new_module_without_import(tmp_path, monkeypatch):
    # Invariant: discovery and install flow must never import module code.
    cm = _make_cfg(tmp_path)
    modules_root = tmp_path / "jarvis" / "modules"
    mod_dir = modules_root / "demo.mod"
    os.makedirs(mod_dir, exist_ok=True)
    # Add a python file that MUST NOT be imported during discovery
    (mod_dir / "impl.py").write_text("raise RuntimeError('imported')\n", encoding="utf-8")
    # Provide a minimal manifest
    _write_module_json(
        str(mod_dir),
        {
            "schema_version": 1,
            "module_id": "demo.mod",
            "version": "0.1.0",
            "display_name": "Demo",
            "description": "",
            "entrypoint": "demo_mod:register",
            "intents": [],
            "module_defaults": {"enabled_by_default": False, "admin_required_to_enable": False},
        },
    )

    def boom(*_a, **_k):
        raise AssertionError("import attempted during discovery")

    monkeypatch.setattr(importlib, "import_module", boom)

    mm = ModuleManager(config_manager=cm, modules_root=str(modules_root), runtime_dir=str(tmp_path / "runtime"), event_bus=None, logger=_L(), security_manager=None)
    out = mm.scan(trace_id="t")
    assert out["ok"] is True
    reg = mm.list_registry().get("modules") or {}
    assert "demo.mod" in reg


def test_wizard_writes_manifest_and_registry_when_missing(tmp_path):
    # Invariant: missing module.json triggers template creation and registry install.
    cm = _make_cfg(tmp_path)
    modules_root = tmp_path / "jarvis" / "modules"
    mod_dir = modules_root / "demo.missing"
    os.makedirs(mod_dir, exist_ok=True)
    # no module.json

    mm = ModuleManager(config_manager=cm, modules_root=str(modules_root), runtime_dir=str(tmp_path / "runtime"), event_bus=None, logger=_L(), security_manager=None)
    _ = mm.scan(trace_id="t")
    assert (mod_dir / "module.json").exists()
    reg = mm.list_registry().get("modules") or {}
    assert "demo.missing" in reg
    assert bool(reg["demo.missing"].get("installed")) is True


def test_safe_auto_enable_only_for_safe_caps(tmp_path):
    # Invariant: safe auto-enable only for SAFE_CAPS and light/inline.
    cm = _make_cfg(tmp_path)
    modules_root = tmp_path / "jarvis" / "modules"

    safe_dir = modules_root / "safe.one"
    _write_module_json(
        str(safe_dir),
        {
            "schema_version": 1,
            "module_id": "safe.one",
            "version": "0.1.0",
            "display_name": "Safe",
            "description": "",
            "entrypoint": "safe_one:register",
            "intents": [
                {
                    "intent_id": "safe.one.ping",
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

    risky_dir = modules_root / "risky.one"
    _write_module_json(
        str(risky_dir),
        {
            "schema_version": 1,
            "module_id": "risky.one",
            "version": "0.1.0",
            "display_name": "Risky",
            "description": "",
            "entrypoint": "risky_one:register",
            "intents": [
                {
                    "intent_id": "risky.one.net",
                    "description": "",
                    "args_schema": {},
                    "required_capabilities": ["CAP_NETWORK_ACCESS"],
                    "resource_class": "light",
                    "execution_mode": "inline",
                }
            ],
            "module_defaults": {"enabled_by_default": False, "admin_required_to_enable": False},
        },
    )

    mm = ModuleManager(config_manager=cm, modules_root=str(modules_root), runtime_dir=str(tmp_path / "runtime"), event_bus=None, logger=_L(), security_manager=None)
    _ = mm.scan(trace_id="t")
    reg = mm.list_registry().get("modules") or {}
    assert bool(reg["safe.one"]["enabled"]) is True
    assert bool(reg["safe.one"]["safe_auto_enabled"]) is True
    assert bool(reg["risky.one"]["enabled"]) is False
    assert bool(reg["risky.one"]["requires_admin_to_enable"]) is True


def test_enable_requires_admin_for_risky_module(tmp_path):
    # Invariant: risky modules require admin approval to enable.
    cm = _make_cfg(tmp_path)
    modules_root = tmp_path / "jarvis" / "modules"
    mod_dir = modules_root / "risky.two"
    _write_module_json(
        str(mod_dir),
        {
            "schema_version": 1,
            "module_id": "risky.two",
            "version": "0.1.0",
            "display_name": "Risky",
            "description": "",
            "entrypoint": "risky_two:register",
            "intents": [
                {
                    "intent_id": "risky.two.net",
                    "description": "",
                    "args_schema": {},
                    "required_capabilities": ["CAP_NETWORK_ACCESS"],
                    "resource_class": "light",
                    "execution_mode": "inline",
                }
            ],
            "module_defaults": {"enabled_by_default": False, "admin_required_to_enable": False},
        },
    )

    store = SecureStore(usb_key_path=str(tmp_path / "usb_missing.bin"), store_path=str(tmp_path / "store.enc"))
    sec = SecurityManager(secure_store=store, admin_session=AdminSession(timeout_seconds=9999))
    mm = ModuleManager(config_manager=cm, modules_root=str(modules_root), runtime_dir=str(tmp_path / "runtime"), event_bus=None, logger=_L(), security_manager=sec)
    _ = mm.scan(trace_id="t")
    assert mm.enable("risky.two", trace_id="t") is False
    sec.admin_session.unlock()
    assert mm.enable("risky.two", trace_id="t") is True


def test_dispatcher_denies_uninstalled_or_disabled_module_intent(tmp_path):
    # Invariant: dispatcher must hard-deny module intents when module is not installed+enabled.
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
            "intents": [
                {
                    "intent_id": "safe.three.ping",
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

    store = SecureStore(usb_key_path=str(tmp_path / "usb_missing.bin"), store_path=str(tmp_path / "store.enc"))
    sec = SecurityManager(secure_store=store, admin_session=AdminSession(timeout_seconds=9999))
    mm = ModuleManager(config_manager=cm, modules_root=str(modules_root), runtime_dir=str(tmp_path / "runtime"), event_bus=None, logger=_L(), security_manager=sec)

    # Cap engine uses updated capabilities.json after scan sync
    def _cap_engine():
        caps_raw = cm.read_non_sensitive("capabilities.json")
        cap_cfg = validate_and_normalize(caps_raw)
        return CapabilityEngine(cfg=cap_cfg, audit=CapabilityAuditLogger(path=str(tmp_path / "sec.jsonl")), logger=None)

    # Prepare dispatcher and a handler spy
    called = {"n": 0}

    def handler(intent_id, args, context):  # noqa: ANN001
        called["n"] += 1
        return {"ok": True}

    reg = ModuleRegistry()
    reg.register_handler(
        module_id="safe.three",
        module_path="test.safe.three",
        meta={"resource_class": "light", "execution_mode": "inline", "required_capabilities": ["CAP_AUDIO_OUTPUT"]},
        handler=handler,
    )

    disp = Dispatcher(
        registry=reg,
        policy=PermissionPolicy(intents={}),
        security=sec,
        event_logger=EventLogger(str(tmp_path / "events.jsonl")),
        logger=_L(),
        capability_engine=_cap_engine(),
        secure_store=store,
        module_manager=mm,
        inline_intent_allowlist=["safe.three.ping"],
    )

    # Not scanned/installed yet -> deny
    r0 = disp.dispatch("t", "safe.three.ping", "safe.three", {}, {"source": "cli"})
    assert r0.ok is False
    assert called["n"] == 0

    _ = mm.scan(trace_id="t")
    disp.capability_engine = _cap_engine()

    # Auto-enabled (safe) -> allowed
    r1 = disp.dispatch("t", "safe.three.ping", "safe.three", {}, {"source": "cli"})
    assert r1.ok is True
    assert called["n"] == 1

    # Disable -> deny
    mm.disable("safe.three", trace_id="t")
    r2 = disp.dispatch("t", "safe.three.ping", "safe.three", {}, {"source": "cli"})
    assert r2.ok is False
    assert called["n"] == 1


def test_changed_module_requires_review(tmp_path):
    # Invariant: contract-changing updates disable module and require review.
    cm = _make_cfg(tmp_path)
    modules_root = tmp_path / "jarvis" / "modules"
    mod_dir = modules_root / "safe.change"
    _write_module_json(
        str(mod_dir),
        {
            "schema_version": 1,
            "module_id": "safe.change",
            "version": "0.1.0",
            "display_name": "Safe",
            "description": "",
            "entrypoint": "safe_change:register",
            "intents": [
                {
                    "intent_id": "safe.change.ping",
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

    mm = ModuleManager(config_manager=cm, modules_root=str(modules_root), runtime_dir=str(tmp_path / "runtime"), event_bus=None, logger=_L(), security_manager=None)
    _ = mm.scan(trace_id="t")
    reg = mm.list_registry().get("modules") or {}
    assert bool(reg["safe.change"]["enabled"]) is True

    # Contract change: add CAP_NETWORK_ACCESS
    _write_module_json(
        str(mod_dir),
        {
            "schema_version": 1,
            "module_id": "safe.change",
            "version": "0.1.1",
            "display_name": "Safe",
            "description": "changed",
            "entrypoint": "safe_change:register",
            "intents": [
                {
                    "intent_id": "safe.change.ping",
                    "description": "",
                    "args_schema": {},
                    "required_capabilities": ["CAP_NETWORK_ACCESS"],
                    "resource_class": "light",
                    "execution_mode": "inline",
                }
            ],
            "module_defaults": {"enabled_by_default": False, "admin_required_to_enable": False},
        },
    )
    _ = mm.scan(trace_id="t2")
    reg2 = mm.list_registry().get("modules") or {}
    assert bool(reg2["safe.change"]["enabled"]) is False
    assert bool(reg2["safe.change"]["changed_requires_review"]) is True

