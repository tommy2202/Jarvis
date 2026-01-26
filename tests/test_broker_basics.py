from __future__ import annotations

import json

from jarvis.core.broker.registry import ToolRegistry
from jarvis.core.broker.write_broker import WriteBroker
from jarvis.core.config.manager import ConfigManager
from jarvis.core.config.paths import ConfigFsPaths
from jarvis.core.crypto import generate_usb_master_key_bytes, write_usb_key
from jarvis.core.privacy.gates import persistence_context
from jarvis.core.privacy.store import PrivacyStore
from jarvis.core.secure_store import SecureStore
from jarvis.core.security_events import SecurityAuditLogger


class _L:
    def info(self, *_a, **_k): ...
    def warning(self, *_a, **_k): ...
    def error(self, *_a, **_k): ...


def _make_cfg(tmp_path) -> ConfigManager:
    cm = ConfigManager(fs=ConfigFsPaths(str(tmp_path)), logger=_L(), read_only=False)
    cm.load_all()
    return cm


def _make_secure_store(tmp_path) -> SecureStore:
    usb = tmp_path / "usb.bin"
    write_usb_key(str(usb), generate_usb_master_key_bytes())
    return SecureStore(usb_key_path=str(usb), store_path=str(tmp_path / "store.enc"))


def _allow_persistence(cm: ConfigManager) -> None:
    raw = cm.read_non_sensitive("privacy.json") or {}
    raw.setdefault("data_minimization", {})
    raw["data_minimization"]["disable_persistent_user_text"] = False
    cm.save_non_sensitive("privacy.json", raw)


def test_unknown_tool_denied_and_audited(tmp_path):
    audit_path = tmp_path / "security.jsonl"
    registry = ToolRegistry(audit_logger=SecurityAuditLogger(path=str(audit_path)))
    res = registry.run("unknown.tool", {"token": "secret"}, {"trace_id": "t"})
    assert res.allowed is False
    assert res.reason_code == "unknown_tool"
    data = [json.loads(line) for line in audit_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    assert data
    assert all("secret" not in json.dumps(row) for row in data)


def test_write_broker_denies_in_ephemeral_mode(tmp_path):
    cm = _make_cfg(tmp_path)
    _allow_persistence(cm)
    ps = PrivacyStore(db_path=str(tmp_path / "runtime" / "privacy.sqlite"), config_manager=cm, event_bus=None, logger=_L())
    store = _make_secure_store(tmp_path)
    ps.set_consent(user_id="default", scope="memory", granted=True, trace_id="t", actor_is_admin=True)
    broker = WriteBroker(privacy_store=ps, secure_store=store, audit_logger=SecurityAuditLogger(path=str(tmp_path / "security.jsonl")))

    with persistence_context(persist_allowed=False):
        res = broker.run("write.memory", {"content": "hello", "user_id": "default"}, {"trace_id": "t2"})
        assert res.allowed is False
        assert res.reason_code == "ephemeral_mode"

    assert store.list_keys(prefix="memory:") == []
    assert ps.list_records(user_id="default", limit=50) == []
