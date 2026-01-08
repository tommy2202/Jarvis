from __future__ import annotations

import os
import time
from typing import Any, Dict, List, Tuple

from jarvis.core.config.io import atomic_write_json, backup_file
from jarvis.core.config.paths import ConfigFsPaths

from jarvis.core.config.migrations.migration_0001_initial import migrate as mig_0001
from jarvis.core.config.migrations.migration_0002_web_hardening import migrate as mig_0002


MIGRATIONS: List[Tuple[int, Any]] = [
    (1, mig_0001),
    (2, mig_0002),
]


def latest_version() -> int:
    return max(v for v, _ in MIGRATIONS)


def run_migrations(
    *,
    fs: ConfigFsPaths,
    files: Dict[str, Dict[str, Any]],
    current_version: int,
    backups_dir: str,
    max_backups: int,
    write_back: bool,
) -> Tuple[Dict[str, Dict[str, Any]], int, List[str]]:
    """
    Pure-dict migration runner. Optionally writes back migrated files with backups.
    """
    logs: List[str] = []
    out = dict(files)
    ver = int(current_version)
    for target_version, fn in MIGRATIONS:
        if target_version <= ver:
            continue
        out, ver = fn(out)
        logs.append(f"applied migration {target_version:04d}")

    if logs:
        app = dict(out.get("app.json") or {})
        app["config_version"] = ver
        app["last_migrated_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        out["app.json"] = app

    if write_back and logs:
        # write each mutated file back to config dir
        for name, data in out.items():
            path = os.path.join(fs.config_dir, name)
            atomic_write_json(path, data, backups_dir, max_backups=max_backups)
    return out, ver, logs

