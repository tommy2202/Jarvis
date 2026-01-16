from __future__ import annotations

import json

from jarvis.core.capabilities.audit import CapabilityAuditLogger
from jarvis.core.capabilities.engine import CapabilityEngine
from jarvis.core.capabilities.loader import default_config_dict, validate_and_normalize
from jarvis.core.crypto import generate_usb_master_key_bytes, write_usb_key
from jarvis.core.dispatcher import Dispatcher
from jarvis.core.events import EventLogger
from jarvis.core.flags import FeatureFlagManager
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


def test_flag_disabled_blocks_feature(tmp_path):
    flags_path = tmp_path / "feature_flags.json"
    flags_path.write_text(json.dumps({"flags": {"demo.flag": {"enabled": False}}}, indent=2) + "\n", encoding="utf-8")

    ff = FeatureFlagManager(
        flags_path=str(flags_path),
        backups_dir=str(tmp_path / "backups"),
        security_manager=None,
        audit_logger=SecurityAuditLogger(path=str(tmp_path / "security.jsonl")),
        read_only=True,
    )

    sec, store = _security(tmp_path)
    reg = ModuleRegistry()

    def handler(intent_id, args, context):  # noqa: ANN001
        return {"ok": True}

    reg.register_handler(
        module_id="demo",
        module_path="test.demo",
        meta={"resource_class": "default", "execution_mode": "inline", "required_capabilities": [], "feature_flag": "demo.flag"},
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
        feature_flags=ff,
    )
    res = disp.dispatch("t1", "demo.run", "demo", {}, {"source": "cli"})
    assert res.ok is False
    assert res.denied_reason == "feature_flag_disabled"
    assert "Feature flag disabled" in res.reply


def test_flag_enable_audited(tmp_path):
    flags_path = tmp_path / "feature_flags.json"
    audit_path = tmp_path / "security.jsonl"
    ff = FeatureFlagManager(
        flags_path=str(flags_path),
        backups_dir=str(tmp_path / "backups"),
        security_manager=DummySecurity(is_admin=True),
        audit_logger=SecurityAuditLogger(path=str(audit_path)),
    )

    assert ff.set_flag("demo.flag", True, trace_id="t-flag", actor="admin") is True
    assert ff.is_enabled("demo.flag") is True

    data = [json.loads(line) for line in audit_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    assert data
    last = data[-1]
    assert last.get("trace_id") == "t-flag"
    assert last.get("event") == "feature_flag.changed"
    assert last.get("details", {}).get("flag") == "demo.flag"
    assert last.get("details", {}).get("enabled") is True
