from __future__ import annotations

import os

import pytest


def test_corrupt_state_recovers_to_last_known_good(tmp_path, monkeypatch):
    from jarvis.core.ops_log import OpsLogger
    from jarvis.core.runtime_state.manager import RuntimeStateManager, RuntimeStateManagerConfig
    from jarvis.core.runtime_state.io import RuntimeStatePaths, atomic_write_json, write_last_known_good
    from jarvis.core.runtime_state.models import RuntimeState

    monkeypatch.chdir(tmp_path)
    paths = RuntimeStatePaths(runtime_dir=str(tmp_path / "runtime"))
    os.makedirs(paths.runtime_dir, exist_ok=True)

    good = RuntimeState().model_dump()
    good["state_machine"]["last_state"] = "IDLE"
    atomic_write_json(paths.state_path, good, backups_dir=paths.backups_dir, keep=5)
    write_last_known_good(paths)

    # corrupt primary
    with open(paths.state_path, "w", encoding="utf-8") as f:
        f.write("{not json")

    ops = OpsLogger(path=str(tmp_path / "logs" / "ops.jsonl"))
    m = RuntimeStateManager(cfg=RuntimeStateManagerConfig(enabled=False, paths={"runtime_dir": paths.runtime_dir}), ops=ops, logger=None)
    st = m.load()
    assert st.state_machine.last_state == "IDLE"


def test_dirty_shutdown_flag_sets_recovery_note(tmp_path, monkeypatch):
    from jarvis.core.ops_log import OpsLogger
    from jarvis.core.runtime_state.manager import RuntimeStateManager, RuntimeStateManagerConfig
    from jarvis.core.runtime_state.io import RuntimeStatePaths, mark_dirty

    monkeypatch.chdir(tmp_path)
    paths = RuntimeStatePaths(runtime_dir=str(tmp_path / "runtime"))
    mark_dirty(paths, "prev")

    ops = OpsLogger(path=str(tmp_path / "logs" / "ops.jsonl"))
    m = RuntimeStateManager(cfg=RuntimeStateManagerConfig(enabled=False, paths={"runtime_dir": paths.runtime_dir}), ops=ops, logger=None)
    m.load()
    m.mark_dirty_startup()
    snap = m.get_snapshot()
    assert snap["crash"]["dirty_shutdown_detected"] is True
    assert snap["security"]["admin_locked"] is True

