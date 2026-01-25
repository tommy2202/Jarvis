from __future__ import annotations

import time

from jarvis.core.capabilities.audit import CapabilityAuditLogger
from jarvis.core.capabilities.engine import CapabilityEngine
from jarvis.core.capabilities.loader import default_config_dict, validate_and_normalize
from jarvis.core.crypto import generate_usb_master_key_bytes, write_usb_key
from jarvis.core.dispatcher import Dispatcher
from jarvis.core.events import EventLogger
from jarvis.core.events.bus import EventBus, EventBusConfig
from jarvis.core.module_registry import ModuleRegistry
from jarvis.core.security import AdminSession, PermissionPolicy, SecurityManager
from jarvis.core.secure_store import SecureStore


class DummyLogger:
    def error(self, *_a, **_k): ...


def _make_security(tmp_path):
    usb = tmp_path / "usb.bin"
    write_usb_key(str(usb), generate_usb_master_key_bytes())
    store = SecureStore(usb_key_path=str(usb), store_path=str(tmp_path / "store.enc"))
    sec = SecurityManager(secure_store=store, admin_session=AdminSession(timeout_seconds=9999))
    return sec, store


def _make_dispatcher(tmp_path, *, intent_id: str, allow: bool):
    sec, store = _make_security(tmp_path)
    reg = ModuleRegistry()

    def handler(intent_id, args, context):  # noqa: ANN001
        return {"ok": True, "summary": "Handled."}

    reg.register_handler(
        module_id="demo",
        module_path="test.demo",
        meta={"resource_class": "default", "execution_mode": "inline", "required_capabilities": []},
        handler=handler,
    )

    raw = default_config_dict()
    if allow:
        raw["intent_requirements"][intent_id] = []
    cfg = validate_and_normalize(raw)
    eng = CapabilityEngine(cfg=cfg, audit=CapabilityAuditLogger(path=str(tmp_path / "security.jsonl")), logger=None)

    bus = EventBus(cfg=EventBusConfig(enabled=True, max_queue_size=100, worker_threads=1), logger=None)
    events = []
    bus.subscribe("ux.*", lambda ev: events.append(ev), priority=10)

    disp = Dispatcher(
        registry=reg,
        policy=PermissionPolicy(intents={}),
        security=sec,
        event_logger=EventLogger(str(tmp_path / "events.jsonl")),
        logger=DummyLogger(),
        capability_engine=eng,
        secure_store=store,
        event_bus=bus,
        inline_intent_allowlist=[intent_id],
    )
    return disp, bus, events


def test_acknowledge_emitted(tmp_path):
    disp, bus, events = _make_dispatcher(tmp_path, intent_id="demo.run", allow=True)
    try:
        res = disp.dispatch("t1", "demo.run", "demo", {}, {"source": "cli"})
        assert res.ok is True
        time.sleep(0.2)
        assert any(ev.event_type == "ux.acknowledge" for ev in events)
    finally:
        bus.shutdown(0.5)


def test_completion_emitted(tmp_path):
    disp, bus, events = _make_dispatcher(tmp_path, intent_id="demo.run", allow=True)
    try:
        res = disp.dispatch("t2", "demo.run", "demo", {}, {"source": "cli"})
        assert res.ok is True
        time.sleep(0.2)
        assert any(ev.event_type == "ux.completed" for ev in events)
    finally:
        bus.shutdown(0.5)


def test_failure_contains_remediation(tmp_path):
    disp, bus, events = _make_dispatcher(tmp_path, intent_id="demo.denied", allow=False)
    try:
        res = disp.dispatch("t3", "demo.denied", "demo", {}, {"source": "cli"})
        assert res.ok is False
        time.sleep(0.2)
        failed_events = [ev for ev in events if ev.event_type == "ux.failed"]
        assert failed_events
        remediation = str((failed_events[-1].payload or {}).get("remediation") or "")
        assert remediation
    finally:
        bus.shutdown(0.5)
