from __future__ import annotations

import json
import os

from jarvis.core.config.manager import ConfigManager
from jarvis.core.config.paths import ConfigFsPaths
from jarvis.core.privacy.models import DataCategory, DataRecord, LawfulBasis, Sensitivity, StorageKind
from jarvis.core.privacy.store import PrivacyStore


class _L:
    def info(self, *_a, **_k): ...
    def warning(self, *_a, **_k): ...
    def error(self, *_a, **_k): ...


def _make_cfg(tmp_path) -> ConfigManager:
    cm = ConfigManager(fs=ConfigFsPaths(str(tmp_path)), logger=_L(), read_only=False)
    cm.load_all()
    return cm


def _write_privacy_policy(cm: ConfigManager, *, category: str, sensitivity: str, ttl_days: int, deletion_action: str, review_required: bool) -> None:
    raw = cm.read_non_sensitive("privacy.json") or {}
    raw.setdefault("schema_version", 1)
    raw.setdefault("default_user_id", "default")
    raw.setdefault("data_minimization", {})
    raw.setdefault("default_consent_scopes", {})
    pols = raw.get("retention_policies") or []
    if not isinstance(pols, list):
        pols = []
    pols = [p for p in pols if not (isinstance(p, dict) and str(p.get("data_category") or "").upper() == category and str(p.get("sensitivity") or "").upper() == sensitivity)]
    pols.append({"data_category": category, "sensitivity": sensitivity, "ttl_days": int(ttl_days), "deletion_action": deletion_action, "review_required": bool(review_required)})
    raw["retention_policies"] = pols
    cm.save_non_sensitive("privacy.json", raw)


def test_expired_records_deleted(tmp_path):
    cm = _make_cfg(tmp_path)
    _write_privacy_policy(cm, category="ERROR_LOG", sensitivity="LOW", ttl_days=1, deletion_action="delete", review_required=False)

    file_path = tmp_path / "logs" / "todelete.jsonl"
    os.makedirs(file_path.parent, exist_ok=True)
    file_path.write_text("x\n", encoding="utf-8")

    ps = PrivacyStore(db_path=str(tmp_path / "runtime" / "privacy.sqlite"), config_manager=cm, event_bus=None, logger=_L())
    rec = DataRecord(
        user_id="default",
        data_category=DataCategory.ERROR_LOG,
        sensitivity=Sensitivity.LOW,
        lawful_basis=LawfulBasis.LEGITIMATE_INTERESTS,
        created_at="2026-01-01T00:00:00Z",
        storage_kind=StorageKind.FILE,
        storage_ref=str(file_path),
        storage_ref_hash="h",
        producer="test",
    )
    rid = ps.register_record(rec)
    assert os.path.exists(file_path)

    res = ps.retention_run(trace_id="t", now_iso="2026-01-13T00:00:00Z")
    assert res["deleted"] >= 1
    assert os.path.exists(file_path) is False
    rows = ps.list_records(user_id="default", limit=200)
    assert all(r.record_id != rid for r in rows)


def test_review_required_creates_pending(tmp_path):
    cm = _make_cfg(tmp_path)
    _write_privacy_policy(cm, category="JOB_ARTIFACT", sensitivity="MEDIUM", ttl_days=1, deletion_action="delete", review_required=True)

    file_path = tmp_path / "runtime" / "artifact.bin"
    os.makedirs(file_path.parent, exist_ok=True)
    file_path.write_bytes(b"abc")

    ps = PrivacyStore(db_path=str(tmp_path / "runtime" / "privacy.sqlite"), config_manager=cm, event_bus=None, logger=_L())
    rid = ps.register_record(
        DataRecord(
            user_id="default",
            data_category=DataCategory.JOB_ARTIFACT,
            sensitivity=Sensitivity.MEDIUM,
            lawful_basis=LawfulBasis.LEGITIMATE_INTERESTS,
            created_at="2026-01-01T00:00:00Z",
            storage_kind=StorageKind.FILE,
            storage_ref=str(file_path),
            storage_ref_hash="h2",
            producer="test",
        )
    )
    res = ps.retention_run(trace_id="t", now_iso="2026-01-13T00:00:00Z")
    assert res["pending_review"] >= 1
    assert os.path.exists(file_path) is True
    pend = ps.retention_pending(limit=50)
    assert any(p.get("record_id") == rid for p in pend)


def test_approve_executes_deletion(tmp_path):
    cm = _make_cfg(tmp_path)
    _write_privacy_policy(cm, category="JOB_ARTIFACT", sensitivity="MEDIUM", ttl_days=1, deletion_action="delete", review_required=True)

    file_path = tmp_path / "runtime" / "artifact2.bin"
    os.makedirs(file_path.parent, exist_ok=True)
    file_path.write_bytes(b"abc")

    ps = PrivacyStore(db_path=str(tmp_path / "runtime" / "privacy.sqlite"), config_manager=cm, event_bus=None, logger=_L())
    rid = ps.register_record(
        DataRecord(
            user_id="default",
            data_category=DataCategory.JOB_ARTIFACT,
            sensitivity=Sensitivity.MEDIUM,
            lawful_basis=LawfulBasis.LEGITIMATE_INTERESTS,
            created_at="2026-01-01T00:00:00Z",
            storage_kind=StorageKind.FILE,
            storage_ref=str(file_path),
            storage_ref_hash="h3",
            producer="test",
        )
    )
    _ = ps.retention_run(trace_id="t", now_iso="2026-01-13T00:00:00Z")
    pend = ps.retention_pending(limit=50)
    action_id = next(p["action_id"] for p in pend if p.get("record_id") == rid)

    ok = ps.retention_approve(action_id=action_id, trace_id="t", actor_is_admin=True)
    assert ok is True
    assert os.path.exists(file_path) is False
    assert all(p["action_id"] != action_id for p in ps.retention_pending(limit=50))
    assert all(r.record_id != rid for r in ps.list_records(user_id="default", limit=200))

