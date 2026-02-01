from __future__ import annotations

from jarvis.core.capabilities.audit import CapabilityAuditLogger
from jarvis.core.capabilities.engine import CapabilityEngine
from jarvis.core.capabilities.loader import default_config_dict, validate_and_normalize
from jarvis.core.crypto import generate_usb_master_key_bytes, write_usb_key
from jarvis.core.dispatcher import Dispatcher
from jarvis.core.events import EventLogger
from jarvis.core.module_registry import LoadedModule, ModuleRegistry
from jarvis.core.security import AdminSession, PermissionPolicy, SecurityManager
from jarvis.core.secure_store import SecureStore


class _L:
    def info(self, *_a, **_k): ...
    def warning(self, *_a, **_k): ...
    def error(self, *_a, **_k): ...


def test_denial_response_includes_introspection_fields(tmp_path):
    usb = tmp_path / "usb.bin"
    write_usb_key(str(usb), generate_usb_master_key_bytes())
    store = SecureStore(usb_key_path=str(usb), store_path=str(tmp_path / "store.enc"))
    sec = SecurityManager(secure_store=store, admin_session=AdminSession(timeout_seconds=999))

    raw = default_config_dict()
    raw["intent_requirements"]["demo.run"] = ["CAP_ADMIN_ACTION"]
    cfg = validate_and_normalize(raw)
    eng = CapabilityEngine(cfg=cfg, audit=CapabilityAuditLogger(path=str(tmp_path / "security.jsonl")), logger=None)

    reg = ModuleRegistry()
    reg._modules_by_id["demo"] = LoadedModule(  # noqa: SLF001
        module_path="test.demo",
        module_id="demo",
        meta={"resource_class": "light", "execution_mode": "inline", "required_capabilities": ["CAP_ADMIN_ACTION"]},
        _unsafe_handler=lambda **_k: {"ok": True},
    )

    disp = Dispatcher(
        registry=reg,
        policy=PermissionPolicy(intents={}),
        security=sec,
        event_logger=EventLogger(str(tmp_path / "events.jsonl")),
        logger=_L(),
        capability_engine=eng,
        secure_store=store,
    )

    res = disp.dispatch("trace-introspect", "demo.run", "demo", {}, {"source": "cli"})
    assert res.ok is False
    breakdown = res.decision_breakdown or {}
    assert breakdown.get("denied_by")
    assert breakdown.get("reason_code")
    assert breakdown.get("remediation")
    assert breakdown.get("trace_id") == "trace-introspect"
