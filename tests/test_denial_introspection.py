from __future__ import annotations

import os

from jarvis.core.capabilities.audit import CapabilityAuditLogger
from jarvis.core.capabilities.engine import CapabilityEngine
from jarvis.core.capabilities.loader import default_config_dict, validate_and_normalize
from jarvis.core.config.manager import ConfigManager
from jarvis.core.config.paths import ConfigFsPaths
from jarvis.core.dispatcher import Dispatcher
from jarvis.core.events import EventLogger
from jarvis.core.module_registry import LoadedModule, ModuleRegistry
from jarvis.core.modules.cli import modules_status_lines
from jarvis.core.modules.manager import ModuleManager
from jarvis.core.security import AdminSession, PermissionPolicy, SecurityManager
from jarvis.core.secure_store import SecureStore
from jarvis.core.crypto import generate_usb_master_key_bytes, write_usb_key


class _L:
    def info(self, *_a, **_k): ...
    def warning(self, *_a, **_k): ...
    def error(self, *_a, **_k): ...


def _make_cfg(tmp_path) -> ConfigManager:
    cm = ConfigManager(fs=ConfigFsPaths(str(tmp_path)), logger=_L(), read_only=False)
    cm.load_all()
    return cm


def test_denial_includes_decision_breakdown(tmp_path):
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

    res = disp.dispatch("t1", "demo.run", "demo", {}, {"source": "cli"})
    assert res.ok is False
    assert res.decision_breakdown is not None
    assert res.decision_breakdown.get("denied_by") == "capabilities"
    assert res.decision_breakdown.get("reason_code") == "capability_denied"
    assert res.decision_breakdown.get("remediation")
    assert res.decision_breakdown.get("trace_id") == "t1"


def test_modules_status_shows_blocked_reason(tmp_path):
    cm = _make_cfg(tmp_path)
    modules_root = tmp_path / "jarvis" / "modules"
    os.makedirs(modules_root / "demo.blocked", exist_ok=True)

    mm = ModuleManager(config_manager=cm, modules_root=str(modules_root), runtime_dir=str(tmp_path / "runtime"), event_bus=None, logger=_L(), security_manager=None)
    out = "\n".join(modules_status_lines(module_manager=mm, trace_id="t"))
    assert "demo.blocked" in out
    assert "NO_MANIFEST" in out
