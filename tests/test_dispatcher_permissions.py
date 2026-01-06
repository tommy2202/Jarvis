from __future__ import annotations

from jarvis.core.dispatcher import Dispatcher
from jarvis.core.events import EventLogger
from jarvis.core.module_registry import ModuleRegistry
from jarvis.core.security import AdminSession, PermissionPolicy, SecurityManager
from jarvis.core.secure_store import SecureStore
from jarvis.core.crypto import generate_usb_master_key_bytes, write_usb_key


class DummyLogger:
    def error(self, *_a, **_k): ...


def _sec(tmp_path):
    usb = tmp_path / "usb.bin"
    write_usb_key(str(usb), generate_usb_master_key_bytes())
    store = SecureStore(usb_key_path=str(usb), store_path=str(tmp_path / "store.enc"), meta_path=str(tmp_path / "meta.json"), backups_dir=str(tmp_path / "b"))
    return SecurityManager(secure_store=store, admin_session=AdminSession(timeout_seconds=9999))


def test_network_access_flag_is_admin_only_fail_safe(tmp_path):
    sec = _sec(tmp_path)
    reg = ModuleRegistry()
    reg.register("jarvis.modules.music")
    policy = PermissionPolicy(intents={"music.play": {"requires_admin": False, "resource_intensive": False, "network_access": True}})
    d = Dispatcher(registry=reg, policy=policy, security=sec, event_logger=EventLogger(str(tmp_path / "e.jsonl")), logger=DummyLogger())
    res = d.dispatch("t", "music.play", "music", {"song": "x", "service": "Spotify"}, {})
    assert res.ok is False
    assert "Admin required" in res.reply

