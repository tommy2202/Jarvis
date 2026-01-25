from __future__ import annotations

from jarvis.core.capabilities.audit import CapabilityAuditLogger
from jarvis.core.capabilities.engine import CapabilityEngine
from jarvis.core.capabilities.loader import default_config_dict, validate_and_normalize
from jarvis.core.dispatcher import Dispatcher
from jarvis.core.events import EventLogger
from jarvis.core.module_registry import LoadedModule, ModuleRegistry
from jarvis.core.modules.models import ExecutionMode
from jarvis.core.modules.wizard import validate_manifest_dict
from jarvis.core.security import AdminSession, PermissionPolicy, SecurityManager
from jarvis.core.secure_store import SecureStore
from jarvis.core.crypto import generate_usb_master_key_bytes, write_usb_key


def test_missing_execution_mode_defaults_to_process():
    raw = {
        "schema_version": 1,
        "module_id": "demo.mode",
        "version": "0.1.0",
        "display_name": "Demo Mode",
        "description": "",
        "entrypoint": "demo_mode:register",
        "intents": [
            {
                "intent_id": "demo.mode.ping",
                "description": "",
                "args_schema": {},
                "required_capabilities": [],
                "resource_class": "light",
            }
        ],
        "module_defaults": {"enabled_by_default": False, "admin_required_to_enable": False},
    }
    man, err = validate_manifest_dict(raw)
    assert man is not None, err
    assert man.intents[0].execution_mode == ExecutionMode.process


def test_process_enforced_for_risky_caps_even_if_manifest_inline(tmp_path):
    usb = tmp_path / "usb.bin"
    write_usb_key(str(usb), generate_usb_master_key_bytes())
    store = SecureStore(usb_key_path=str(usb), store_path=str(tmp_path / "store.enc"))
    sec = SecurityManager(secure_store=store, admin_session=AdminSession(timeout_seconds=9999))
    sec.admin_session.unlock()

    raw = default_config_dict()
    raw["intent_requirements"]["risky.run"] = ["CAP_RUN_SUBPROCESS"]
    cfg = validate_and_normalize(raw)
    eng = CapabilityEngine(cfg=cfg, audit=CapabilityAuditLogger(path=str(tmp_path / "security.jsonl")), logger=None)

    handler_called = {"n": 0}
    process_called = {"n": 0}

    def handler(intent_id, args, context):  # noqa: ANN001
        handler_called["n"] += 1
        return {"ok": True}

    reg = ModuleRegistry()
    reg._modules_by_id["risky"] = LoadedModule(  # noqa: SLF001
        module_path="test.risky",
        module_id="risky",
        meta={"resource_class": "light", "execution_mode": "inline", "required_capabilities": ["CAP_RUN_SUBPROCESS"]},
        _unsafe_handler=handler,
    )

    disp = Dispatcher(
        registry=reg,
        policy=PermissionPolicy(intents={}),
        security=sec,
        event_logger=EventLogger(str(tmp_path / "events.jsonl")),
        logger=type("L", (), {"error": lambda *_a, **_k: None})(),
        capability_engine=eng,
        secure_store=store,
        inline_intent_allowlist=["risky.run"],
    )

    def fake_run(module_path, intent_id, args, context, internal_call=False):  # noqa: ANN001
        process_called["n"] += 1
        return {"ok": True}

    disp._run_in_subprocess = fake_run  # type: ignore[assignment]

    res = disp.dispatch("t1", "risky.run", "risky", {}, {"source": "cli"})
    assert res.ok is True
    assert process_called["n"] == 1
    assert handler_called["n"] == 0


def test_allowlisted_core_intent_can_run_inline(tmp_path):
    usb = tmp_path / "usb.bin"
    write_usb_key(str(usb), generate_usb_master_key_bytes())
    store = SecureStore(usb_key_path=str(usb), store_path=str(tmp_path / "store.enc"))
    sec = SecurityManager(secure_store=store, admin_session=AdminSession(timeout_seconds=9999))
    sec.admin_session.unlock()

    raw = default_config_dict()
    raw["intent_requirements"]["core.time.now"] = []
    cfg = validate_and_normalize(raw)
    eng = CapabilityEngine(cfg=cfg, audit=CapabilityAuditLogger(path=str(tmp_path / "security.jsonl")), logger=None)

    handler_called = {"n": 0}
    process_called = {"n": 0}

    def handler(intent_id, args, context):  # noqa: ANN001
        handler_called["n"] += 1
        return {"ok": True}

    reg = ModuleRegistry()
    reg._modules_by_id["core.time"] = LoadedModule(  # noqa: SLF001
        module_path="test.core.time",
        module_id="core.time",
        meta={"core": True, "resource_class": "light", "execution_mode": "inline", "required_capabilities": []},
        _unsafe_handler=handler,
    )

    disp = Dispatcher(
        registry=reg,
        policy=PermissionPolicy(intents={}),
        security=sec,
        event_logger=EventLogger(str(tmp_path / "events.jsonl")),
        logger=type("L", (), {"error": lambda *_a, **_k: None})(),
        capability_engine=eng,
        secure_store=store,
        inline_intent_allowlist=["core.time.now"],
    )

    def fake_run(module_path, intent_id, args, context, internal_call=False):  # noqa: ANN001
        process_called["n"] += 1
        return {"ok": True}

    disp._run_in_subprocess = fake_run  # type: ignore[assignment]

    res = disp.dispatch("t1", "core.time.now", "core.time", {}, {"source": "cli"})
    assert res.ok is True
    assert handler_called["n"] == 1
    assert process_called["n"] == 0
