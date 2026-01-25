from __future__ import annotations

import pytest

from jarvis.core.capabilities.audit import CapabilityAuditLogger
from jarvis.core.capabilities.engine import CapabilityEngine
from jarvis.core.capabilities.loader import default_config_dict, validate_and_normalize
from jarvis.core.crypto import generate_usb_master_key_bytes, write_usb_key
from jarvis.core.dispatcher import Dispatcher
from jarvis.core.events import EventLogger
from jarvis.core.module_registry import ModuleRegistry
from jarvis.core.security import AdminSession, PermissionPolicy, SecurityManager
from jarvis.core.secure_store import SecureStore


class DummyLogger:
    def error(self, *_a, **_k): ...


def _security(tmp_path):
    usb = tmp_path / "usb.bin"
    write_usb_key(str(usb), generate_usb_master_key_bytes())
    store = SecureStore(usb_key_path=str(usb), store_path=str(tmp_path / "store.enc"))
    sec = SecurityManager(secure_store=store, admin_session=AdminSession(timeout_seconds=9999))
    return sec, store


def test_dispatcher_executes_loaded_module_safely(tmp_path):
    sec, store = _security(tmp_path)
    reg = ModuleRegistry()
    called = {"n": 0}

    def handler(intent_id, args, context):  # noqa: ANN001
        called["n"] += 1
        return {"summary": "ok"}

    reg.register_handler(
        module_id="demo",
        module_path="test.demo",
        meta={"resource_class": "default", "execution_mode": "inline", "required_capabilities": []},
        handler=handler,
    )

    policy = PermissionPolicy(intents={"demo.run": {"requires_admin": False, "resource_intensive": False}})
    raw = default_config_dict()
    raw["intent_requirements"]["demo.run"] = []
    raw["safe_mode"] = {"deny": []}
    raw["source_policies"] = {}
    cap_cfg = validate_and_normalize(raw)
    eng = CapabilityEngine(cfg=cap_cfg, audit=CapabilityAuditLogger(path=str(tmp_path / "security.jsonl")), logger=None)
    disp = Dispatcher(
        registry=reg,
        policy=policy,
        security=sec,
        event_logger=EventLogger(str(tmp_path / "events.jsonl")),
        logger=DummyLogger(),
        capability_engine=eng,
        secure_store=store,
        inline_intent_allowlist=["demo.run"],
    )

    res = disp.dispatch("t1", "demo.run", "demo", {}, {"source": "cli"})
    assert res.ok is True
    assert called["n"] == 1


def test_loaded_module_handler_access_is_unsafe(tmp_path):
    reg = ModuleRegistry()

    def handler(intent_id, args, context):  # noqa: ANN001
        return {"ok": True}

    loaded = reg.register_handler(
        module_id="demo",
        module_path="test.demo",
        meta={"resource_class": "default", "execution_mode": "inline", "required_capabilities": []},
        handler=handler,
    )

    with pytest.raises(RuntimeError, match="unsafe"):
        _ = loaded.handler
