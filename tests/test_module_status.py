from __future__ import annotations

import json
import os

from jarvis.core.config.manager import ConfigManager
from jarvis.core.config.paths import ConfigFsPaths
from jarvis.core.dispatcher import Dispatcher
from jarvis.core.events import EventLogger
from jarvis.core.module_registry import ModuleRegistry
from jarvis.core.modules.cli import modules_list_lines
from jarvis.core.modules.manager import ModuleManager
from jarvis.core.modules.models import ModuleReasonCode, ModuleState
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


def test_status_reason_no_manifest(tmp_path):
    cm = _make_cfg(tmp_path)
    modules_root = tmp_path / "jarvis" / "modules"
    os.makedirs(modules_root / "demo.nomani", exist_ok=True)  # no module.json

    mm = ModuleManager(config_manager=cm, modules_root=str(modules_root), runtime_dir=str(tmp_path / "runtime"), event_bus=None, logger=_L(), security_manager=None)
    st = mm.get_status("demo.nomani", trace_id="t")
    assert st.state == ModuleState.BLOCKED
    assert st.reason_code == ModuleReasonCode.NO_MANIFEST


def test_status_reason_manifest_invalid(tmp_path):
    cm = _make_cfg(tmp_path)
    modules_root = tmp_path / "jarvis" / "modules"
    mod_dir = modules_root / "demo.badman"
    _write_module_json(
        str(mod_dir),
        {
            "schema_version": 1,
            "module_id": "demo.badman",
            "version": "0.1.0",
            "display_name": "Bad",
            "description": "",
            # entrypoint is required and must be non-empty
            "entrypoint": "",
            "intents": [],
            "module_defaults": {"enabled_by_default": False, "admin_required_to_enable": False},
        },
    )

    mm = ModuleManager(config_manager=cm, modules_root=str(modules_root), runtime_dir=str(tmp_path / "runtime"), event_bus=None, logger=_L(), security_manager=None)
    st = mm.get_status("demo.badman", trace_id="t")
    assert st.state == ModuleState.BLOCKED
    assert st.reason_code == ModuleReasonCode.MANIFEST_INVALID


def test_status_reason_caps_mapping_missing(tmp_path):
    cm = _make_cfg(tmp_path)
    modules_root = tmp_path / "jarvis" / "modules"
    mod_dir = modules_root / "demo.missingcaps"
    _write_module_json(
        str(mod_dir),
        {
            "schema_version": 1,
            "module_id": "demo.missingcaps",
            "version": "0.1.0",
            "display_name": "Demo",
            "description": "",
            "entrypoint": "demo_missingcaps:register",
            "intents": [
                {
                    "intent_id": "demo.missingcaps.ping",
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

    # Do NOT scan (scan would sync mappings); status must still reflect missing mapping.
    mm = ModuleManager(config_manager=cm, modules_root=str(modules_root), runtime_dir=str(tmp_path / "runtime"), event_bus=None, logger=_L(), security_manager=None)
    st = mm.get_status("demo.missingcaps", trace_id="t")
    assert st.state == ModuleState.BLOCKED
    assert st.reason_code == ModuleReasonCode.CAPABILITIES_MAPPING_MISSING


def test_dispatcher_denial_includes_reason_and_remediation(tmp_path):
    cm = _make_cfg(tmp_path)
    modules_root = tmp_path / "jarvis" / "modules"
    os.makedirs(modules_root / "demo.nomani", exist_ok=True)  # no module.json

    store = SecureStore(usb_key_path=str(tmp_path / "usb_missing.bin"), store_path=str(tmp_path / "store.enc"))
    sec = SecurityManager(secure_store=store, admin_session=AdminSession(timeout_seconds=9999))
    mm = ModuleManager(config_manager=cm, modules_root=str(modules_root), runtime_dir=str(tmp_path / "runtime"), event_bus=None, logger=_L(), security_manager=sec)

    called = {"n": 0}

    def handler(intent_id, args, context):  # noqa: ANN001
        called["n"] += 1
        return {"ok": True}

    reg = ModuleRegistry()
    reg.register_handler(module_id="demo.nomani", module_path="test.demo.nomani", meta={"resource_class": "light", "execution_mode": "inline", "required_capabilities": []}, handler=handler)
    disp = Dispatcher(
        registry=reg,
        policy=PermissionPolicy(intents={}),
        security=sec,
        event_logger=EventLogger(str(tmp_path / "events.jsonl")),
        logger=_L(),
        capability_engine=None,  # not reached; module gate denies first
        secure_store=store,
        module_manager=mm,
    )

    r = disp.dispatch("t", "demo.nomani.ping", "demo.nomani", {}, {"source": "cli"})
    assert r.ok is False
    assert called["n"] == 0
    assert "NO_MANIFEST" in r.reply
    assert "Run /modules scan" in r.reply


def test_modules_list_cli_contains_reason_columns(tmp_path):
    cm = _make_cfg(tmp_path)
    modules_root = tmp_path / "jarvis" / "modules"
    os.makedirs(modules_root / "demo.nomani", exist_ok=True)  # no module.json
    mm = ModuleManager(config_manager=cm, modules_root=str(modules_root), runtime_dir=str(tmp_path / "runtime"), event_bus=None, logger=_L(), security_manager=None)

    out = "\n".join(modules_list_lines(module_manager=mm, trace_id="t"))
    assert "module_id | state | enabled | reason_code | remediation" in out
    assert "reason_code" in out
    assert "remediation" in out

