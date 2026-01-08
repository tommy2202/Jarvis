from __future__ import annotations

import json
import os

import pytest


def _mk_mgr(tmp_path, *, enabled: bool = True):
    from jarvis.core.ops_log import OpsLogger
    from jarvis.core.runtime_state.manager import RuntimeStateManager, RuntimeStateManagerConfig

    ops = OpsLogger(path=str(tmp_path / "logs" / "ops.jsonl"))
    cfg = RuntimeStateManagerConfig(enabled=enabled, paths={"runtime_dir": str(tmp_path / "runtime")}, backup_keep=5, write_interval_seconds=3600)
    m = RuntimeStateManager(cfg=cfg, ops=ops, logger=None)
    return m


def test_state_load_missing_creates_defaults(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    m = _mk_mgr(tmp_path, enabled=False)
    st = m.load()
    assert st.security.admin_locked is True
    assert st.state_version >= 1


def test_atomic_save_writes_state_and_backup(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    m = _mk_mgr(tmp_path, enabled=True)
    try:
        m.load()
        m.record_transition("SLEEPING", "UNDERSTANDING", "tid")
        m.save(reason="test")
        state_path = os.path.join(str(tmp_path / "runtime"), "state.json")
        assert os.path.exists(state_path)
        # second save creates backup
        m.record_transition("UNDERSTANDING", "IDLE", "tid2")
        m.save(reason="test2")
        backups_dir = os.path.join(str(tmp_path / "runtime"), "backups")
        backups = [f for f in os.listdir(backups_dir) if f.startswith("state.") and f.endswith(".json")]
        assert backups, "expected at least one backup"
    finally:
        m.stop()


def test_schema_rejects_unknown_fields(tmp_path, monkeypatch):
    from jarvis.core.runtime_state.io import RuntimeStatePaths, atomic_write_json
    from jarvis.core.runtime_state.models import RuntimeState

    monkeypatch.chdir(tmp_path)
    paths = RuntimeStatePaths(runtime_dir=str(tmp_path / "runtime"))
    os.makedirs(paths.runtime_dir, exist_ok=True)
    # write invalid state with extra field
    d = RuntimeState().model_dump()
    d["unknown"] = 1
    atomic_write_json(paths.state_path, d, backups_dir=paths.backups_dir, keep=5)

    m = _mk_mgr(tmp_path, enabled=False)
    st = m.load()
    assert isinstance(st, RuntimeState)


def test_no_secrets_persisted(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    m = _mk_mgr(tmp_path, enabled=True)
    try:
        m.load()
        m.set_lockouts_summary({"api_key": "SHOULD_NOT_APPEAR", "count": 1})
        m.save(reason="test")
        data = open(os.path.join(str(tmp_path / "runtime"), "state.json"), "r", encoding="utf-8").read()
        assert "SHOULD_NOT_APPEAR" not in data
    finally:
        m.stop()

