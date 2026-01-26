from __future__ import annotations

import json

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
    def info(self, *_a, **_k): ...
    def warning(self, *_a, **_k): ...
    def error(self, *_a, **_k): ...


def _security(tmp_path):
    usb = tmp_path / "usb.bin"
    write_usb_key(str(usb), generate_usb_master_key_bytes())
    store = SecureStore(usb_key_path=str(usb), store_path=str(tmp_path / "store.enc"), meta_path=str(tmp_path / "meta.json"), backups_dir=str(tmp_path / "b"))
    sec = SecurityManager(secure_store=store, admin_session=AdminSession(timeout_seconds=999))
    return sec, store


def test_denied_never_executes_handler_and_audits(tmp_path):
    sec, store = _security(tmp_path)
    raw = default_config_dict()
    raw["intent_requirements"]["demo.run"] = ["CAP_ADMIN_ACTION"]
    cap_cfg = validate_and_normalize(raw)
    cap_engine = CapabilityEngine(cfg=cap_cfg, audit=CapabilityAuditLogger(path=str(tmp_path / "security.jsonl")), logger=None)
    ev_path = tmp_path / "events.jsonl"
    events = EventLogger(str(ev_path))

    called = {"n": 0}

    def handler(intent_id, args, context):  # noqa: ANN001
        called["n"] += 1
        return {"ok": True}

    reg = ModuleRegistry()
    reg.register_handler(
        module_id="demo",
        module_path="test.demo",
        meta={"resource_class": "light", "execution_mode": "inline", "required_capabilities": ["CAP_ADMIN_ACTION"]},
        handler=handler,
    )

    dispatcher = Dispatcher(
        registry=reg,
        policy=PermissionPolicy(intents={}),
        security=sec,
        event_logger=events,
        logger=DummyLogger(),
        capability_engine=cap_engine,
        secure_store=store,
    )

    res = dispatcher.dispatch("trace-deny", "demo.run", "demo", {}, {"source": "cli"})
    assert res.ok is False
    assert called["n"] == 0

    rows = [json.loads(line) for line in ev_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    assert any(r.get("event") == "dispatch.denied" and r.get("trace_id") == "trace-deny" for r in rows)
