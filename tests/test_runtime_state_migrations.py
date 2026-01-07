from __future__ import annotations

import os


def test_migration_from_old_state_version(tmp_path, monkeypatch):
    from jarvis.core.ops_log import OpsLogger
    from jarvis.core.runtime_state.io import RuntimeStatePaths, atomic_write_json
    from jarvis.core.runtime_state.manager import RuntimeStateManager, RuntimeStateManagerConfig

    monkeypatch.chdir(tmp_path)
    paths = RuntimeStatePaths(runtime_dir=str(tmp_path / "runtime"))
    os.makedirs(paths.runtime_dir, exist_ok=True)
    # write old version
    atomic_write_json(paths.state_path, {"state_version": 0}, backups_dir=paths.backups_dir, keep=5)

    ops = OpsLogger(path=str(tmp_path / "logs" / "ops.jsonl"))
    m = RuntimeStateManager(cfg=RuntimeStateManagerConfig(enabled=False, paths={"runtime_dir": paths.runtime_dir}), ops=ops, logger=None)
    st = m.load()
    assert st.state_version >= 1

