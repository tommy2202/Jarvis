from __future__ import annotations

import json

from jarvis.core.capabilities.audit import CapabilityAuditLogger
from jarvis.core.capabilities.engine import CapabilityEngine
from jarvis.core.capabilities.loader import default_config_dict, validate_and_normalize
from jarvis.core.crypto import generate_usb_master_key_bytes, write_usb_key
from jarvis.core.dispatcher import Dispatcher
from jarvis.core.events import EventLogger
from jarvis.core.lockdown import LockdownConfig, LockdownManager
from jarvis.core.module_registry import ModuleRegistry
from jarvis.core.security import AdminSession, PermissionPolicy, SecurityManager
from jarvis.core.secure_store import SecureStore
from jarvis.core.security_events import SecurityAuditLogger


class DummyLogger:
    def error(self, *_a, **_k): ...


class DummySecurity:
    def __init__(self, *, is_admin: bool = True):
        self._is_admin = bool(is_admin)

    def is_admin(self) -> bool:
        return self._is_admin


def _security(tmp_path):
    usb = tmp_path / "usb.bin"
    write_usb_key(str(usb), generate_usb_master_key_bytes())
    store = SecureStore(usb_key_path=str(usb), store_path=str(tmp_path / "store.enc"))
    sec = SecurityManager(secure_store=store, admin_session=AdminSession(timeout_seconds=9999))
    return sec, store


def test_lockdown_triggered(tmp_path):
    audit_path = tmp_path / "security.jsonl"
    lockdown = LockdownManager(
        cfg=LockdownConfig(admin_failure_threshold=2, admin_failure_window_seconds=60.0),
        security_manager=DummySecurity(is_admin=True),
        audit_logger=SecurityAuditLogger(path=str(audit_path)),
    )

    lockdown.record_admin_failure(trace_id="t1", source="cli")
    assert lockdown.is_active() is False

    lockdown.record_admin_failure(trace_id="t2", source="cli")
    assert lockdown.is_active() is True

    lines = [json.loads(line) for line in audit_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    assert any(l.get("event") == "security.lockdown_entered" for l in lines)

    assert lockdown.exit_lockdown(trace_id="t3", actor="admin", reason="test") is True
    assert lockdown.is_active() is False

    lines = [json.loads(line) for line in audit_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    assert any(l.get("event") == "security.lockdown_exited" for l in lines)


def test_lockdown_blocks_execution(tmp_path):
    lockdown = LockdownManager(
        cfg=LockdownConfig(deny_burst_threshold=1, deny_burst_window_seconds=10.0),
        audit_logger=SecurityAuditLogger(path=str(tmp_path / "security.jsonl")),
    )
    lockdown.enter_lockdown(trace_id="t0", reason="test")

    sec, store = _security(tmp_path)
    reg = ModuleRegistry()
    called = {"count": 0}

    def handler(intent_id, args, context):  # noqa: ANN001
        called["count"] += 1
        return {"ok": True}

    reg.register_handler(
        module_id="demo",
        module_path="test.demo",
        meta={"resource_class": "default", "execution_mode": "inline", "required_capabilities": []},
        handler=handler,
    )

    raw = default_config_dict()
    raw["intent_requirements"]["demo.run"] = []
    cap_cfg = validate_and_normalize(raw)
    eng = CapabilityEngine(cfg=cap_cfg, audit=CapabilityAuditLogger(path=str(tmp_path / "security.jsonl")), logger=None)

    disp = Dispatcher(
        registry=reg,
        policy=PermissionPolicy(intents={}),
        security=sec,
        event_logger=EventLogger(str(tmp_path / "events.jsonl")),
        logger=DummyLogger(),
        capability_engine=eng,
        secure_store=store,
        lockdown_manager=lockdown,
    )

    res = disp.dispatch("t1", "demo.run", "demo", {}, {"source": "cli"})
    assert res.ok is False
    assert res.denied_reason == "lockdown_active"
    assert called["count"] == 0
