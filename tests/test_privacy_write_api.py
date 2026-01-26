from __future__ import annotations

import json

from jarvis.core.config.manager import ConfigManager
from jarvis.core.config.paths import ConfigFsPaths
from jarvis.core.crypto import generate_usb_master_key_bytes, write_usb_key
from jarvis.core.privacy.gates import persistence_context
from jarvis.core.privacy.models import DataCategory, DataRecord, LawfulBasis, Sensitivity, StorageKind
from jarvis.core.privacy.store import PrivacyStore
from jarvis.core.privacy.write_api import write_artifact_metadata, write_memory
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
    raw["data_minimization"]["disable_persistent_transcripts"] = False
    cm.save_non_sensitive("privacy.json", raw)


def test_ephemeral_denies_memory_and_artifact(tmp_path):
    cm = _make_cfg(tmp_path)
    _allow_persistence(cm)
    ps = PrivacyStore(db_path=str(tmp_path / "runtime" / "privacy.sqlite"), config_manager=cm, event_bus=None, logger=_L())
    store = _make_secure_store(tmp_path)
    ps.set_consent(user_id="default", scope="memory", granted=True, trace_id="t", actor_is_admin=True)

    rec = DataRecord(
        user_id="default",
        data_category=DataCategory.JOB_ARTIFACT,
        sensitivity=Sensitivity.MEDIUM,
        lawful_basis=LawfulBasis.LEGITIMATE_INTERESTS,
        created_at="2026-01-01T00:00:00Z",
        storage_kind=StorageKind.FILE,
        storage_ref=str(tmp_path / "runtime" / "artifact.bin"),
        storage_ref_hash="",
        producer="test",
    )

    with persistence_context(persist_allowed=False):
        dec = write_memory(privacy_store=ps, secure_store=store, trace_id="t1", user_id="default", content="secret")
        assert dec.allowed is False
        assert dec.reason_code == "ephemeral_mode"

        dec2 = write_artifact_metadata(privacy_store=ps, record=rec, trace_id="t2")
        assert dec2.allowed is False
        assert dec2.reason_code == "ephemeral_mode"

    assert store.list_keys(prefix="memory:") == []
    assert ps.list_records(user_id="default", limit=50) == []


def test_consent_allows_memory_write(tmp_path):
    cm = _make_cfg(tmp_path)
    _allow_persistence(cm)
    ps = PrivacyStore(db_path=str(tmp_path / "runtime" / "privacy.sqlite"), config_manager=cm, event_bus=None, logger=_L())
    store = _make_secure_store(tmp_path)
    ps.set_consent(user_id="default", scope="memory", granted=True, trace_id="t", actor_is_admin=True)

    dec = write_memory(privacy_store=ps, secure_store=store, trace_id="t3", user_id="default", content="hello world")
    assert dec.allowed is True
    assert dec.reason_code == "allowed"

    keys = store.list_keys(prefix="memory:")
    assert keys
    recs = ps.list_records(user_id="default", limit=50)
    assert any(r.data_category == DataCategory.MEMORY for r in recs)


def test_write_decisions_are_audited_and_redacted(tmp_path):
    cm = _make_cfg(tmp_path)
    _allow_persistence(cm)
    ps = PrivacyStore(db_path=str(tmp_path / "runtime" / "privacy.sqlite"), config_manager=cm, event_bus=None, logger=_L())
    store = _make_secure_store(tmp_path)
    ps.set_consent(user_id="default", scope="memory", granted=True, trace_id="t", actor_is_admin=True)

    audit_path = tmp_path / "security.jsonl"
    audit_logger = SecurityAuditLogger(path=str(audit_path))
    dec = write_memory(privacy_store=ps, secure_store=store, trace_id="t4", user_id="default", content="supersecret", audit_logger=audit_logger)
    assert dec.allowed is True

    data = [json.loads(line) for line in audit_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    assert data
    last = data[-1]
    assert last.get("event") == "privacy.write"
    assert last.get("details", {}).get("reason_code") in {"allowed", "ephemeral_mode", "consent_missing", "config_disabled"}
    assert "supersecret" not in audit_path.read_text(encoding="utf-8")
