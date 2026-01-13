from __future__ import annotations

import json
import os
import zipfile

from jarvis.core.config.manager import ConfigManager
from jarvis.core.config.paths import ConfigFsPaths
from jarvis.core.privacy.dsar import DsarEngine
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


def _set_dsar_export_allow_copy(cm: ConfigManager, cats: list[str]) -> None:
    raw = cm.read_non_sensitive("privacy.json") or {}
    raw.setdefault("dsar", {})
    raw["dsar"].setdefault("export", {})
    raw["dsar"]["export"]["allow_copy_categories"] = list(cats)
    cm.save_non_sensitive("privacy.json", raw)


def _set_dsar_delete_cfg(cm: ConfigManager, cats: list[str], action: str = "delete") -> None:
    raw = cm.read_non_sensitive("privacy.json") or {}
    raw.setdefault("dsar", {})
    raw["dsar"].setdefault("delete", {})
    raw["dsar"]["delete"]["categories"] = list(cats)
    raw["dsar"]["delete"]["deletion_action"] = str(action)
    cm.save_non_sensitive("privacy.json", raw)


def test_export_zip_created(tmp_path):
    cm = _make_cfg(tmp_path)
    _set_dsar_export_allow_copy(cm, ["JOB_ARTIFACT"])

    # Create a redaction target log entry (must not leak token)
    sec_path = tmp_path / "logs" / "security.jsonl"
    os.makedirs(sec_path.parent, exist_ok=True)
    sec_path.write_text(json.dumps({"ts": "2026-01-01T00:00:00Z", "trace_id": "t", "event": "x", "details": {"token": "SECRET"}}) + "\n", encoding="utf-8")

    # Create a user-owned artifact
    art = tmp_path / "runtime" / "artifact.txt"
    os.makedirs(art.parent, exist_ok=True)
    art.write_text("hello\n", encoding="utf-8")

    ps = PrivacyStore(db_path=str(tmp_path / "runtime" / "privacy.sqlite"), config_manager=cm, event_bus=None, logger=_L())
    ps.register_record(
        DataRecord(
            user_id="default",
            data_category=DataCategory.JOB_ARTIFACT,
            sensitivity=Sensitivity.MEDIUM,
            lawful_basis=LawfulBasis.LEGITIMATE_INTERESTS,
            created_at="2026-01-01T00:00:00Z",
            storage_kind=StorageKind.FILE,
            storage_ref=str(art),
            storage_ref_hash="h",
            producer="test",
        )
    )
    eng = DsarEngine(store=ps, root_path=str(tmp_path))
    rid = eng.request(user_id="default", request_type="export", payload={}, trace_id="t")
    req = eng.run(request_id=rid, actor_is_admin=True, trace_id="t")
    assert req.export_path and os.path.exists(req.export_path)

    with zipfile.ZipFile(req.export_path, "r") as z:
        names = set(z.namelist())
        assert "metadata/data_records.json" in names
        assert "logs/security.jsonl" in names
        # artifact should be copied because allowed
        assert any(n.startswith("artifacts/JOB_ARTIFACT/") for n in names)
        sec = z.read("logs/security.jsonl").decode("utf-8", errors="ignore")
        assert "SECRET" not in sec


def test_delete_removes_records_and_blobs(tmp_path):
    cm = _make_cfg(tmp_path)
    _set_dsar_delete_cfg(cm, ["JOB_ARTIFACT"], action="delete")

    art = tmp_path / "runtime" / "todelete.bin"
    os.makedirs(art.parent, exist_ok=True)
    art.write_bytes(b"abc")

    ps = PrivacyStore(db_path=str(tmp_path / "runtime" / "privacy.sqlite"), config_manager=cm, event_bus=None, logger=_L())
    rid = ps.register_record(
        DataRecord(
            user_id="default",
            data_category=DataCategory.JOB_ARTIFACT,
            sensitivity=Sensitivity.MEDIUM,
            lawful_basis=LawfulBasis.LEGITIMATE_INTERESTS,
            created_at="2026-01-01T00:00:00Z",
            storage_kind=StorageKind.FILE,
            storage_ref=str(art),
            storage_ref_hash="h2",
            producer="test",
        )
    )
    assert os.path.exists(art)

    eng = DsarEngine(store=ps, root_path=str(tmp_path))
    did = eng.request(user_id="default", request_type="delete", payload={}, trace_id="t")
    _ = eng.run(request_id=did, actor_is_admin=True, trace_id="t")

    assert os.path.exists(art) is False
    assert all(r.record_id != rid for r in ps.list_records(user_id="default", limit=200))


def test_restrict_blocks_scope(tmp_path):
    cm = _make_cfg(tmp_path)
    ps = PrivacyStore(db_path=str(tmp_path / "runtime" / "privacy.sqlite"), config_manager=cm, event_bus=None, logger=_L())
    eng = DsarEngine(store=ps, root_path=str(tmp_path))

    rid = eng.request(user_id="default", request_type="restrict", payload={"scopes": ["memory"]}, trace_id="t")
    _ = eng.run(request_id=rid, actor_is_admin=True, trace_id="t")
    assert ps.is_scope_restricted(user_id="default", scope="memory") is True

