from __future__ import annotations

from types import SimpleNamespace

from jarvis.core.dispatcher import Dispatcher
from jarvis.core.error_reporter import ErrorReporter
from jarvis.core.events import EventLogger
from jarvis.core.module_registry import ModuleRegistry, LoadedModule
from jarvis.core.security import AdminSession, PermissionPolicy, SecurityManager
from jarvis.core.secure_store import SecureStore
from jarvis.core.crypto import generate_usb_master_key_bytes, write_usb_key
from jarvis.core.capabilities.audit import CapabilityAuditLogger
from jarvis.core.capabilities.engine import CapabilityEngine
from jarvis.core.capabilities.loader import default_config_dict, validate_and_normalize


class DummyLogger:
    def error(self, *_a, **_k): ...


def test_dispatcher_never_crashes_on_module_exception(tmp_path):
    # minimal security
    usb = tmp_path / "usb.bin"
    write_usb_key(str(usb), generate_usb_master_key_bytes())
    store = SecureStore(usb_key_path=str(usb), store_path=str(tmp_path / "secure.enc"), meta_path=str(tmp_path / "meta.json"), backups_dir=str(tmp_path / "b"))
    sec = SecurityManager(secure_store=store, admin_session=AdminSession(timeout_seconds=9999))

    policy = PermissionPolicy(intents={"x.run": {"requires_admin": False, "resource_intensive": False}})
    reg = ModuleRegistry()

    def bad_handle(*_a, **_k):
        raise RuntimeError("boom")

    # inject a loaded module directly
    reg._modules_by_id["x"] = LoadedModule(  # type: ignore[attr-defined]
        module_path="jarvis.modules.fake",
        module_id="x",
        meta={"resource_class": "default", "execution_mode": "inline", "required_capabilities": []},
        handler=bad_handle,
    )

    raw = default_config_dict()
    raw["intent_requirements"]["x.run"] = []
    caps_cfg = validate_and_normalize(raw)
    eng = CapabilityEngine(cfg=caps_cfg, audit=CapabilityAuditLogger(path=str(tmp_path / "security.jsonl")), logger=None)

    reporter = ErrorReporter(path=str(tmp_path / "errors.jsonl"))
    d = Dispatcher(
        registry=reg,
        policy=policy,
        security=sec,
        event_logger=EventLogger(str(tmp_path / "events.jsonl")),
        logger=DummyLogger(),
        error_reporter=reporter,
        capability_engine=eng,
        secure_store=store,
    )
    res = d.dispatch("t1", "x.run", "x", {}, {})
    assert res.ok is False
    assert res.reply

