from __future__ import annotations

import time
import uuid

from jarvis.core.audit.timeline import AuditTimelineManager
from jarvis.core.config.manager import ConfigManager
from jarvis.core.config.paths import ConfigFsPaths
from jarvis.core.events.bus import EventBus, EventBusConfig, OverflowPolicy
from jarvis.core.events.models import BaseEvent, EventSeverity, SourceSubsystem
from jarvis.core.identity.manager import IdentityManager
from jarvis.core.security import AdminSession, SecurityManager
from jarvis.core.secure_store import SecureStore
from jarvis.core.crypto import generate_usb_master_key_bytes, write_usb_key
from jarvis.core.privacy.store import PrivacyStore
from jarvis.core.dispatcher import Dispatcher
from jarvis.core.module_registry import ModuleRegistry
from jarvis.core.events import EventLogger
from jarvis.core.security import PermissionPolicy
from jarvis.core.capabilities.engine import CapabilityEngine
from jarvis.core.capabilities.audit import CapabilityAuditLogger
from jarvis.core.capabilities.loader import default_config_dict, validate_and_normalize


class _L:
    def info(self, *_a, **_k): ...
    def warning(self, *_a, **_k): ...
    def error(self, *_a, **_k): ...


def _make_cfg(tmp_path) -> ConfigManager:
    cm = ConfigManager(fs=ConfigFsPaths(str(tmp_path)), logger=_L(), read_only=False)
    cm.load_all()
    return cm


def _make_security(tmp_path) -> SecurityManager:
    usb = tmp_path / "usb.bin"
    write_usb_key(str(usb), generate_usb_master_key_bytes())
    store = SecureStore(usb_key_path=str(usb), store_path=str(tmp_path / "store.enc"))
    return SecurityManager(secure_store=store, admin_session=AdminSession(timeout_seconds=1))


def test_default_user_created(tmp_path):
    cm = _make_cfg(tmp_path)
    ps = PrivacyStore(db_path=str(tmp_path / "runtime" / "privacy.sqlite"), config_manager=cm, event_bus=None, logger=_L())
    sec = _make_security(tmp_path)
    im = IdentityManager(privacy_store=ps, security_manager=sec, logger=_L())
    u = im.load_or_create_default_user()
    # Allow either legacy "default" or UUID, but prefer UUID format when present.
    try:
        _ = uuid.UUID(str(u.user_id))
    except Exception:
        assert str(u.user_id) == "default"


def test_active_user_in_request_context(tmp_path):
    cm = _make_cfg(tmp_path)
    ps = PrivacyStore(db_path=str(tmp_path / "runtime" / "privacy.sqlite"), config_manager=cm, event_bus=None, logger=_L())
    sec = _make_security(tmp_path)
    im = IdentityManager(privacy_store=ps, security_manager=sec, logger=_L())
    _ = im.load_or_create_default_user()

    raw = default_config_dict()
    raw.setdefault("intent_requirements", {})
    raw["intent_requirements"]["x.intent"] = []
    cap_cfg = validate_and_normalize(raw)

    seen = {"user_id": None}

    class _Cap(CapabilityEngine):
        def evaluate(self, ctx):  # noqa: ANN001
            seen["user_id"] = getattr(ctx, "user_id", None)
            return super().evaluate(ctx)

    eng = _Cap(cfg=cap_cfg, audit=CapabilityAuditLogger(path=str(tmp_path / "security.jsonl")), logger=None)

    reg = ModuleRegistry()
    reg.register_handler(module_id="m", module_path="test.m", meta={"resource_class": "light", "execution_mode": "inline", "required_capabilities": []}, handler=lambda **_k: {"ok": True})
    disp = Dispatcher(registry=reg, policy=PermissionPolicy(intents={}), security=sec, event_logger=EventLogger(str(tmp_path / "e.jsonl")), logger=_L(), capability_engine=eng, secure_store=sec.secure_store, identity_manager=im)

    _ = disp.dispatch("t", "x.intent", "m", {}, {"source": "cli"})
    assert seen["user_id"] == im.get_active_user().user_id


def test_admin_session_expires(monkeypatch):
    t = {"now": 1000.0}
    monkeypatch.setattr(time, "time", lambda: t["now"])
    s = AdminSession(timeout_seconds=10)
    s.unlock()
    assert s.is_admin() is True
    t["now"] += 11
    assert s.is_admin() is False


def test_audit_includes_user_id(tmp_path):
    eb = EventBus(cfg=EventBusConfig(enabled=True, max_queue_size=1000, worker_threads=2, overflow_policy=OverflowPolicy.DROP_OLDEST))
    cfg = {
        "enabled": True,
        "store": {"path_jsonl": str(tmp_path / "audit.jsonl"), "use_sqlite_index": True, "sqlite_path": str(tmp_path / "index.sqlite")},
        "integrity": {"enabled": True, "verify_on_startup": False, "verify_last_n": 2000},
        "retention": {"days": 90, "max_events": 50000},
        "export": {"max_rows": 20000},
        "ingest_sources": {"security": str(tmp_path / "security.jsonl"), "ops": str(tmp_path / "ops.jsonl"), "errors": str(tmp_path / "errors.jsonl")},
    }
    audit = AuditTimelineManager(cfg=cfg, logger=None, event_bus=eb, telemetry=None, ops_logger=None)
    audit.start()

    eb.publish_nowait(BaseEvent(event_type="privacy.test", trace_id="t", source_subsystem=SourceSubsystem.audit, severity=EventSeverity.INFO, payload={"user_id": "u-123", "x": 1}))
    # poll briefly for ingestion
    deadline = time.time() + 2.0
    while time.time() < deadline:
        rows = audit.list_events(limit=50)
        hit = [r for r in rows if r.action == "privacy.test"]
        if hit:
            assert hit[0].actor.user_id == "u-123"
            return
        time.sleep(0.05)
    assert False, "audit event not ingested"

