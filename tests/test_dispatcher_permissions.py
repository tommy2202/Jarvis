from __future__ import annotations

from jarvis.core.dispatcher import Dispatcher
from jarvis.core.events import EventLogger
from jarvis.core.module_registry import ModuleRegistry
from jarvis.core.security import AdminSession, PermissionPolicy, SecurityManager
from jarvis.core.secure_store import SecureStore
from jarvis.core.crypto import generate_usb_master_key_bytes, write_usb_key
from jarvis.core.capabilities.audit import CapabilityAuditLogger
from jarvis.core.capabilities.engine import CapabilityEngine
from jarvis.core.capabilities.loader import default_config_dict, validate_and_normalize
from jarvis.core.module_registry import LoadedModule


class DummyLogger:
    def error(self, *_a, **_k): ...


def _sec(tmp_path):
    usb = tmp_path / "usb.bin"
    write_usb_key(str(usb), generate_usb_master_key_bytes())
    store = SecureStore(usb_key_path=str(usb), store_path=str(tmp_path / "store.enc"), meta_path=str(tmp_path / "meta.json"), backups_dir=str(tmp_path / "b"))
    return SecurityManager(secure_store=store, admin_session=AdminSession(timeout_seconds=9999)), store


def test_network_access_flag_is_admin_only_fail_safe(tmp_path):
    sec, store = _sec(tmp_path)
    reg = ModuleRegistry()
    # inject module with enforced contract metadata
    reg._modules_by_id["music"] = LoadedModule(  # noqa: SLF001
        module_path="jarvis.modules.music",
        module_id="music",
        meta={"id": "music", "resource_class": "local", "execution_mode": "inline", "capabilities_by_intent": {"music.play": ["CAP_NETWORK_ACCESS"]}},
        handler=lambda *_a, **_k: {"ok": True},
    )
    policy = PermissionPolicy(intents={})
    raw = default_config_dict()
    raw["intent_requirements"] = {"music.play": ["CAP_NETWORK_ACCESS"]}
    cap_engine = CapabilityEngine(cfg=validate_and_normalize(raw), audit=CapabilityAuditLogger(path=str(tmp_path / "security.jsonl")), logger=None)
    d = Dispatcher(registry=reg, policy=policy, security=sec, event_logger=EventLogger(str(tmp_path / "e.jsonl")), logger=DummyLogger(), capability_engine=cap_engine, secure_store=store)
    res = d.dispatch("t", "music.play", "music", {"song": "x", "service": "Spotify"}, {"client": {"id": "c"}, "source": "cli"})
    assert res.ok is False
    assert "Admin required" in res.reply

