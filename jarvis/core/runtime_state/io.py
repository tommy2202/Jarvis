from __future__ import annotations

import json
import os
import shutil
import tempfile
import time
from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple


@dataclass(frozen=True)
class RuntimeStatePaths:
    runtime_dir: str = "runtime"
    state_file: str = "state.json"

    @property
    def state_path(self) -> str:
        return os.path.join(self.runtime_dir, self.state_file)

    @property
    def tmp_path(self) -> str:
        return os.path.join(self.runtime_dir, self.state_file + ".tmp")

    @property
    def backups_dir(self) -> str:
        return os.path.join(self.runtime_dir, "backups")

    @property
    def last_known_good_dir(self) -> str:
        return os.path.join(self.runtime_dir, "last_known_good")

    @property
    def last_known_good_path(self) -> str:
        return os.path.join(self.last_known_good_dir, self.state_file)

    @property
    def crash_markers_dir(self) -> str:
        return os.path.join(self.runtime_dir, "crash_markers")

    @property
    def dirty_flag(self) -> str:
        return os.path.join(self.crash_markers_dir, "dirty_shutdown.flag")

    @property
    def restart_marker(self) -> str:
        return os.path.join(self.crash_markers_dir, "restart_marker.json")


def ensure_dirs(paths: RuntimeStatePaths) -> None:
    os.makedirs(paths.runtime_dir, exist_ok=True)
    os.makedirs(paths.backups_dir, exist_ok=True)
    os.makedirs(paths.last_known_good_dir, exist_ok=True)
    os.makedirs(paths.crash_markers_dir, exist_ok=True)


def read_json(path: str) -> Tuple[bool, Dict[str, Any], Optional[str]]:
    if not os.path.exists(path):
        return False, {}, "missing"
    try:
        with open(path, "r", encoding="utf-8") as f:
            obj = json.load(f)
        if not isinstance(obj, dict):
            return False, {}, "not_object"
        return True, obj, None
    except json.JSONDecodeError as e:
        return False, {}, f"corrupt_json:{e}"
    except Exception as e:  # noqa: BLE001
        return False, {}, str(e)


def atomic_write_json(path: str, obj: Dict[str, Any], *, backups_dir: str, keep: int = 20) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    os.makedirs(backups_dir, exist_ok=True)

    if os.path.exists(path):
        ts = time.strftime("%Y%m%d_%H%M%S", time.gmtime())
        b = os.path.join(backups_dir, f"state.{ts}.json")
        try:
            shutil.copy2(path, b)
        except Exception:
            pass
        _enforce_backup_retention(backups_dir, keep=keep)

    fd, tmp = tempfile.mkstemp(prefix=".tmp_state_", suffix=".json", dir=os.path.dirname(path))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(obj, f, indent=2, ensure_ascii=False, sort_keys=True)
            f.write("\n")
            try:
                f.flush()
                os.fsync(f.fileno())
            except Exception:
                pass
        os.replace(tmp, path)
    finally:
        try:
            if os.path.exists(tmp):
                os.remove(tmp)
        except OSError:
            pass


def _enforce_backup_retention(backups_dir: str, *, keep: int) -> None:
    try:
        files = [os.path.join(backups_dir, f) for f in os.listdir(backups_dir) if f.startswith("state.") and f.endswith(".json")]
        files.sort(key=lambda p: os.path.getmtime(p), reverse=True)
        for p in files[int(keep) :]:
            try:
                os.remove(p)
            except OSError:
                pass
    except Exception:
        return


def write_last_known_good(paths: RuntimeStatePaths) -> None:
    try:
        if os.path.exists(paths.state_path):
            os.makedirs(paths.last_known_good_dir, exist_ok=True)
            shutil.copy2(paths.state_path, paths.last_known_good_path)
    except Exception:
        return


def recover_from_corrupt(paths: RuntimeStatePaths, *, keep: int = 20) -> Dict[str, Any]:
    """
    On corrupt JSON:
    - move corrupt state to backups/state.<ts>.corrupt.json
    - restore last_known_good if present
    - else return {}
    """
    ensure_dirs(paths)
    if os.path.exists(paths.state_path):
        try:
            ts = time.strftime("%Y%m%d_%H%M%S", time.gmtime())
            dst = os.path.join(paths.backups_dir, f"state.{ts}.corrupt.json")
            shutil.move(paths.state_path, dst)
            _enforce_backup_retention(paths.backups_dir, keep=keep)
        except Exception:
            pass
    ok, data, _ = read_json(paths.last_known_good_path)
    if ok:
        try:
            atomic_write_json(paths.state_path, data, backups_dir=paths.backups_dir, keep=keep)
        except Exception:
            pass
        return data
    return {}


def mark_dirty(paths: RuntimeStatePaths, trace_id: str) -> None:
    ensure_dirs(paths)
    with open(paths.dirty_flag, "w", encoding="utf-8") as f:
        f.write(f"{trace_id}\n")


def clear_dirty(paths: RuntimeStatePaths) -> None:
    try:
        os.remove(paths.dirty_flag)
    except OSError:
        pass


def dirty_exists(paths: RuntimeStatePaths) -> bool:
    return os.path.exists(paths.dirty_flag)


def write_restart_marker(paths: RuntimeStatePaths, payload: Dict[str, Any]) -> None:
    ensure_dirs(paths)
    atomic_write_json(paths.restart_marker, payload, backups_dir=paths.backups_dir, keep=20)


def consume_restart_marker(paths: RuntimeStatePaths) -> Optional[Dict[str, Any]]:
    ok, data, _ = read_json(paths.restart_marker)
    if not ok:
        return None
    try:
        os.remove(paths.restart_marker)
    except OSError:
        pass
    return data

