from __future__ import annotations

import os
import sqlite3

import pytest

from jarvis.core.config.manager import ConfigManager
from jarvis.core.config.paths import ConfigFsPaths
from jarvis.core.privacy.models import DataCategory, DataRecord, RetentionPolicy, Sensitivity
from jarvis.core.privacy.store import PrivacyStore
from jarvis.core.privacy.tagging import data_record_for_file


class _L:
    def info(self, *_a, **_k): ...
    def warning(self, *_a, **_k): ...
    def error(self, *_a, **_k): ...


def _make_cfg(tmp_path) -> ConfigManager:
    cm = ConfigManager(fs=ConfigFsPaths(str(tmp_path)), logger=_L(), read_only=False)
    cm.load_all()
    return cm


def test_create_default_user(tmp_path):
    cm = _make_cfg(tmp_path)
    db_path = tmp_path / "runtime" / "privacy.sqlite"
    ps = PrivacyStore(db_path=str(db_path), config_manager=cm, event_bus=None, logger=_L())
    u = ps.get_or_create_default_user()
    assert u.user_id == "default"
    assert u.is_default is True


def test_register_data_record(tmp_path):
    cm = _make_cfg(tmp_path)
    db_path = tmp_path / "runtime" / "privacy.sqlite"
    ps = PrivacyStore(db_path=str(db_path), config_manager=cm, event_bus=None, logger=_L())

    rec = data_record_for_file(path="logs/errors.jsonl", category=DataCategory.ERROR_LOG, sensitivity=Sensitivity.LOW, trace_id="t1")
    rid = ps.register_record(rec)
    assert rid

    rows = ps.list_records(user_id="default", limit=50)
    assert any(r.record_id == rid for r in rows)


def test_retention_policy_resolves_expires_at():
    pol = RetentionPolicy(data_category=DataCategory.AUDIT, sensitivity=Sensitivity.LOW, ttl_days=1)
    exp = pol.resolve_expires_at(created_at="2026-01-01T00:00:00Z")
    assert exp == "2026-01-02T00:00:00Z"


def test_no_content_logged_in_data_record(tmp_path):
    cm = _make_cfg(tmp_path)
    db_path = tmp_path / "runtime" / "privacy.sqlite"
    ps = PrivacyStore(db_path=str(db_path), config_manager=cm, event_bus=None, logger=_L())

    # Extra "content" field must never be accepted into DataRecord.
    with pytest.raises(Exception):
        _ = DataRecord.model_validate(
            {
                "user_id": "default",
                "data_category": "ERROR_LOG",
                "sensitivity": "LOW",
                "storage_ref": "logs/errors.jsonl",
                "content": "SECRET",
            }
        )

    # Even inside tags, content-like keys must be dropped (store only storage_ref + safe metadata).
    rid = ps.register_record(
        data_record_for_file(
            path="logs/errors.jsonl",
            category=DataCategory.ERROR_LOG,
            sensitivity=Sensitivity.LOW,
            trace_id="t2",
            tags={"format": "jsonl", "content": "SECRET", "text": "SECRET2"},
        )
    )
    assert rid

    recs = ps.list_records(user_id="default", limit=10)
    got = next(r for r in recs if r.record_id == rid)
    assert got.storage_ref == "logs/errors.jsonl"
    assert "content" not in {k.lower() for k in (got.tags or {}).keys()}
    assert "text" not in {k.lower() for k in (got.tags or {}).keys()}

    # Verify sqlite file doesn't contain the raw secret in tags_json
    assert os.path.exists(db_path)
    conn = sqlite3.connect(str(db_path))
    try:
        row = conn.execute("SELECT tags_json FROM data_records WHERE record_id=?", (rid,)).fetchone()
        assert row is not None
        assert "SECRET" not in (row[0] or "")
        assert "SECRET2" not in (row[0] or "")
    finally:
        conn.close()

