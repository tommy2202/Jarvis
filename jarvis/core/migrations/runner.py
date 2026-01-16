from __future__ import annotations

import os
import sqlite3
import time
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

from jarvis.core.config.io import atomic_write_json, read_json_file
from jarvis.core.config.paths import ConfigFsPaths
from jarvis.core.events import EventLogger
from jarvis.core.migrations.registry import VersionRegistry


def run_config_migrations(
    *,
    fs: ConfigFsPaths,
    files: Dict[str, Dict[str, Any]],
    current_version: int,
    backups_dir: str,
    max_backups: int,
    write_back: bool,
    registry: Optional[VersionRegistry] = None,
    event_logger: Optional[EventLogger] = None,
    trace_id: str = "config",
) -> Tuple[Dict[str, Dict[str, Any]], int, List[str]]:
    from jarvis.core.config.migrations import runner as cfg_runner

    out, ver, logs = cfg_runner.run_migrations(
        fs=fs,
        files=files,
        current_version=current_version,
        backups_dir=backups_dir,
        max_backups=max_backups,
        write_back=write_back,
    )
    if registry is not None and write_back:
        applied_versions = [v for v, _ in cfg_runner.MIGRATIONS if int(current_version) < int(v) <= int(ver)]
        for v in applied_versions:
            mig_id = f"config.{int(v):04d}"
            if registry.record_applied(subsystem="config", migration_id=mig_id, version=int(v), trace_id=trace_id, details={"summary": f"config migration {int(v):04d}"}):
                _log_migration(event_logger, trace_id, "config", mig_id, "applied", {"version": int(v)})
    return out, ver, logs


def run_module_registry_migrations(
    *,
    fs: ConfigFsPaths,
    files: Dict[str, Dict[str, Any]],
    backups_dir: str,
    max_backups: int,
    write_back: bool,
    registry: Optional[VersionRegistry] = None,
    event_logger: Optional[EventLogger] = None,
    trace_id: str = "modules",
) -> Tuple[Dict[str, Dict[str, Any]], int, List[str]]:
    from jarvis.core.modules.migrations.migration_0001_initial import migrate as mig_0001

    migrations: List[Tuple[int, Any]] = [(1, mig_0001)]
    out = dict(files)
    cur_ver = int((out.get("modules.json") or {}).get("schema_version") or 0)
    logs: List[str] = []
    changed_files: Set[str] = set()
    for target_version, fn in migrations:
        if int(target_version) <= cur_ver:
            continue
        out, changed = fn(out)
        if changed:
            changed_files.update(changed)
        cur_ver = int(target_version)
        logs.append(f"applied module registry migration {int(target_version):04d}")

    if write_back and logs:
        for name in changed_files:
            path = os.path.join(fs.config_dir, name)
            atomic_write_json(path, out.get(name) or {}, backups_dir, max_backups=max_backups)

    if registry is not None and write_back:
        for target_version, _ in migrations:
            if int(target_version) <= int(cur_ver):
                mig_id = f"modules.{int(target_version):04d}"
                if registry.record_applied(subsystem="module_registry", migration_id=mig_id, version=int(target_version), trace_id=trace_id, details={"summary": f"module registry migration {int(target_version):04d}"}):
                    _log_migration(event_logger, trace_id, "module_registry", mig_id, "applied", {"version": int(target_version)})
    return out, cur_ver, logs


def run_privacy_store_migrations(
    *,
    db_path: str,
    registry: Optional[VersionRegistry] = None,
    event_logger: Optional[EventLogger] = None,
    trace_id: str = "privacy",
) -> Tuple[int, List[str]]:
    from jarvis.core.privacy.migrations.migration_0001_initial import migrate as mig_0001

    migrations: List[Tuple[int, Any]] = [(1, mig_0001)]
    logs: List[str] = []
    ver = 0
    conn = sqlite3.connect(db_path, check_same_thread=False)
    try:
        cur = conn.execute("PRAGMA user_version")
        ver = int(cur.fetchone()[0] or 0)
        for target_version, fn in migrations:
            if int(target_version) <= ver:
                continue
            fn(conn)
            conn.execute(f"PRAGMA user_version={int(target_version)}")
            ver = int(target_version)
            logs.append(f"applied privacy migration {int(target_version):04d}")
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()

    if registry is not None:
        for target_version, _ in migrations:
            if int(target_version) <= int(ver):
                mig_id = f"privacy.{int(target_version):04d}"
                if registry.record_applied(subsystem="privacy_store", migration_id=mig_id, version=int(target_version), trace_id=trace_id, details={"summary": f"privacy migration {int(target_version):04d}"}):
                    _log_migration(event_logger, trace_id, "privacy_store", mig_id, "applied", {"version": int(target_version)})
    return ver, logs


def _log_migration(
    event_logger: Optional[EventLogger],
    trace_id: str,
    subsystem: str,
    migration_id: str,
    outcome: str,
    details: Dict[str, Any],
) -> None:
    if event_logger is None:
        return
    payload = {"subsystem": subsystem, "migration_id": migration_id, "outcome": outcome, **(details or {})}
    try:
        event_logger.log(trace_id, "migration.applied", payload)
    except Exception:
        pass
