from __future__ import annotations

from jarvis.core.capabilities.audit import CapabilityAuditLogger
from jarvis.core.capabilities.engine import CapabilityEngine
from jarvis.core.capabilities.loader import validate_and_normalize
from jarvis.core.config.manager import ConfigManager
from jarvis.core.config.paths import ConfigFsPaths
from jarvis.core.dispatcher import Dispatcher
from jarvis.core.events import EventLogger
from jarvis.core.limits.limiter import Limiter
from jarvis.core.module_registry import ModuleRegistry
from jarvis.core.security import AdminSession, PermissionPolicy, SecurityManager
from jarvis.core.secure_store import SecureStore
from .helpers.config_builders import build_capabilities_config_v1


class _L:
    def info(self, *_a, **_k): ...
    def warning(self, *_a, **_k): ...
    def error(self, *_a, **_k): ...


def _make_cfg(tmp_path) -> ConfigManager:
    cm = ConfigManager(fs=ConfigFsPaths(str(tmp_path)), logger=_L(), read_only=False)
    cm.load_all()
    return cm


def _cap_engine(cm: ConfigManager, tmp_path) -> CapabilityEngine:
    caps_raw = cm.read_non_sensitive("capabilities.json")
    caps_raw = dict(caps_raw or build_capabilities_config_v1())
    caps_raw["intent_requirements"] = {"core.ping": []}
    cm.save_non_sensitive("capabilities.json", caps_raw)
    cap_cfg = validate_and_normalize(cm.read_non_sensitive("capabilities.json"))
    return CapabilityEngine(cfg=cap_cfg, audit=CapabilityAuditLogger(path=str(tmp_path / "sec.jsonl")), logger=None)


def test_rate_limit_exceeded_denied(tmp_path):
    cm = _make_cfg(tmp_path)
    now = {"t": 0.0}
    limiter = Limiter(config_manager=cm, time_fn=lambda: now["t"])
    cm.save_non_sensitive(
        "limits.json",
        {
            "schema_version": 1,
            "default": {"per_minute": 1000, "cooldown_seconds": 0},
            "sources": {"cli": {"per_minute": 1, "cooldown_seconds": 0}},
            "intents": {},
        },
    )

    reg = ModuleRegistry()
    called = {"n": 0}

    def handler(intent_id, args, context):  # noqa: ANN001
        called["n"] += 1
        return {"ok": True}

    reg.register_handler(
        module_id="core",
        module_path="core.test",
        meta={"core": True, "resource_class": "light", "execution_mode": "inline", "required_capabilities": []},
        handler=handler,
    )
    store = SecureStore(usb_key_path=str(tmp_path / "usb_missing.bin"), store_path=str(tmp_path / "store.enc"))
    sec = SecurityManager(secure_store=store, admin_session=AdminSession(timeout_seconds=9999))
    disp = Dispatcher(
        registry=reg,
        policy=PermissionPolicy(intents={}),
        security=sec,
        event_logger=EventLogger(str(tmp_path / "events.jsonl")),
        logger=_L(),
        capability_engine=_cap_engine(cm, tmp_path),
        limiter=limiter,
        inline_intent_allowlist=["core.ping"],
    )

    r1 = disp.dispatch("t", "core.ping", "core", {}, {"source": "cli"})
    assert r1.ok is True
    r2 = disp.dispatch("t", "core.ping", "core", {}, {"source": "cli"})
    assert r2.ok is False
    assert r2.denied_reason == "rate_limited"
    assert called["n"] == 1


def test_rate_limit_recovers(tmp_path):
    cm = _make_cfg(tmp_path)
    now = {"t": 0.0}
    limiter = Limiter(config_manager=cm, time_fn=lambda: now["t"])
    cm.save_non_sensitive(
        "limits.json",
        {
            "schema_version": 1,
            "default": {"per_minute": 1000, "cooldown_seconds": 0},
            "sources": {"cli": {"per_minute": 1, "cooldown_seconds": 0}},
            "intents": {},
        },
    )

    reg = ModuleRegistry()
    called = {"n": 0}

    def handler(intent_id, args, context):  # noqa: ANN001
        called["n"] += 1
        return {"ok": True}

    reg.register_handler(
        module_id="core",
        module_path="core.test",
        meta={"core": True, "resource_class": "light", "execution_mode": "inline", "required_capabilities": []},
        handler=handler,
    )
    store = SecureStore(usb_key_path=str(tmp_path / "usb_missing.bin"), store_path=str(tmp_path / "store.enc"))
    sec = SecurityManager(secure_store=store, admin_session=AdminSession(timeout_seconds=9999))
    disp = Dispatcher(
        registry=reg,
        policy=PermissionPolicy(intents={}),
        security=sec,
        event_logger=EventLogger(str(tmp_path / "events.jsonl")),
        logger=_L(),
        capability_engine=_cap_engine(cm, tmp_path),
        limiter=limiter,
        inline_intent_allowlist=["core.ping"],
    )

    r1 = disp.dispatch("t", "core.ping", "core", {}, {"source": "cli"})
    assert r1.ok is True
    r2 = disp.dispatch("t", "core.ping", "core", {}, {"source": "cli"})
    assert r2.ok is False
    # After 60s, bucket refills one token
    now["t"] = 61.0
    r3 = disp.dispatch("t", "core.ping", "core", {}, {"source": "cli"})
    assert r3.ok is True
    assert called["n"] == 2


def test_admin_override(tmp_path):
    cm = _make_cfg(tmp_path)
    now = {"t": 0.0}
    limiter = Limiter(config_manager=cm, time_fn=lambda: now["t"])
    cm.save_non_sensitive(
        "limits.json",
        {
            "schema_version": 1,
            "default": {"per_minute": 1000, "cooldown_seconds": 0},
            "sources": {"cli": {"per_minute": 1, "cooldown_seconds": 0}},
            "intents": {},
        },
    )

    reg = ModuleRegistry()
    called = {"n": 0}

    def handler(intent_id, args, context):  # noqa: ANN001
        called["n"] += 1
        return {"ok": True}

    reg.register_handler(
        module_id="core",
        module_path="core.test",
        meta={"core": True, "resource_class": "light", "execution_mode": "inline", "required_capabilities": []},
        handler=handler,
    )
    store = SecureStore(usb_key_path=str(tmp_path / "usb_missing.bin"), store_path=str(tmp_path / "store.enc"))
    sec = SecurityManager(secure_store=store, admin_session=AdminSession(timeout_seconds=9999))
    sec.admin_session.unlock()
    disp = Dispatcher(
        registry=reg,
        policy=PermissionPolicy(intents={}),
        security=sec,
        event_logger=EventLogger(str(tmp_path / "events.jsonl")),
        logger=_L(),
        capability_engine=_cap_engine(cm, tmp_path),
        limiter=limiter,
        inline_intent_allowlist=["core.ping"],
    )

    r1 = disp.dispatch("t", "core.ping", "core", {}, {"source": "cli"})
    assert r1.ok is True
    r2 = disp.dispatch("t", "core.ping", "core", {}, {"source": "cli"})
    assert r2.ok is False
    r3 = disp.dispatch("t", "core.ping", "core", {}, {"source": "cli", "diagnostics_override": True})
    assert r3.ok is True
    assert called["n"] == 2

