from __future__ import annotations

import os

from jarvis.core.dispatcher import Dispatcher
from jarvis.core.events import EventLogger
from jarvis.core.module_registry import LoadedModule, ModuleRegistry
from jarvis.core.security import AdminSession, PermissionPolicy, SecurityManager
from jarvis.core.secure_store import SecureStore
from jarvis.core.crypto import generate_usb_master_key_bytes, write_usb_key


def test_dispatcher_blocks_execution_when_capability_denied(tmp_path, monkeypatch):
    from jarvis.core.capabilities.audit import CapabilityAuditLogger
    from jarvis.core.capabilities.engine import CapabilityEngine
    from jarvis.core.capabilities.loader import default_config_dict, validate_and_normalize
    monkeypatch.chdir(tmp_path)

    # Security + secure store (unlocked)
    usb = tmp_path / "usb.bin"
    write_usb_key(str(usb), generate_usb_master_key_bytes())
    store = SecureStore(usb_key_path=str(usb), store_path=str(tmp_path / "store.enc"))
    sec = SecurityManager(secure_store=store, admin_session=AdminSession(timeout_seconds=999))

    # Registry with a handler we can spy on
    called = {"n": 0}

    def handler(intent_id, args, context):  # noqa: ANN001
        called["n"] += 1
        return {"ok": True}

    reg = ModuleRegistry()
    reg._modules_by_id["music"] = LoadedModule(module_path="test", module_id="music", meta={}, handler=handler)  # noqa: SLF001

    policy = PermissionPolicy(intents={"music.play": {"requires_admin": False, "resource_intensive": False, "network_access": False}})

    cfg = validate_and_normalize(default_config_dict())
    # Make music.play require admin action (should be denied without admin)
    cfg.intent_requirements["music.play"] = ["CAP_ADMIN_ACTION"]
    eng = CapabilityEngine(cfg=cfg, audit=CapabilityAuditLogger(path=str(tmp_path / "security.jsonl")), logger=None)

    disp = Dispatcher(registry=reg, policy=policy, security=sec, event_logger=EventLogger(str(tmp_path / "events.jsonl")), logger=type("L", (), {"error": lambda *_a, **_k: None})(), capability_engine=eng, secure_store=store)

    r = disp.dispatch("t1", "music.play", "music", {"song": "x", "service": "y"}, {"client": {"source": "cli"}})
    assert r.ok is False
    assert called["n"] == 0


def test_dispatcher_allows_when_capability_allows(tmp_path, monkeypatch):
    from jarvis.core.capabilities.audit import CapabilityAuditLogger
    from jarvis.core.capabilities.engine import CapabilityEngine
    from jarvis.core.capabilities.loader import default_config_dict, validate_and_normalize

    monkeypatch.chdir(tmp_path)
    usb = tmp_path / "usb.bin"
    write_usb_key(str(usb), generate_usb_master_key_bytes())
    store = SecureStore(usb_key_path=str(usb), store_path=str(tmp_path / "store.enc"))
    sec = SecurityManager(secure_store=store, admin_session=AdminSession(timeout_seconds=999))

    called = {"n": 0}

    def handler(intent_id, args, context):  # noqa: ANN001
        called["n"] += 1
        return {"ok": True}

    reg = ModuleRegistry()
    reg._modules_by_id["music"] = LoadedModule(module_path="test", module_id="music", meta={}, handler=handler)  # noqa: SLF001

    policy = PermissionPolicy(intents={"music.play": {"requires_admin": False, "resource_intensive": False, "network_access": False}})
    cfg = validate_and_normalize(default_config_dict())
    eng = CapabilityEngine(cfg=cfg, audit=CapabilityAuditLogger(path=str(tmp_path / "security.jsonl")), logger=None)

    disp = Dispatcher(registry=reg, policy=policy, security=sec, event_logger=EventLogger(str(tmp_path / "events.jsonl")), logger=type("L", (), {"error": lambda *_a, **_k: None})(), capability_engine=eng, secure_store=store)
    r = disp.dispatch("t2", "music.play", "music", {"song": "x", "service": "y"}, {"client": {"source": "cli"}})
    assert r.ok is True
    assert called["n"] == 1

