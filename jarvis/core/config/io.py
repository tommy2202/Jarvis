from __future__ import annotations

import json
import os
import shutil
import tempfile
import time
from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple


@dataclass(frozen=True)
class ReadResult:
    ok: bool
    data: Dict[str, Any]
    error: Optional[str] = None
    was_recovered: bool = False


def _ts() -> str:
    return time.strftime("%Y%m%d_%H%M%S", time.gmtime())


def ensure_dirs(*dirs: str) -> None:
    for d in dirs:
        os.makedirs(d, exist_ok=True)


def read_json_file(path: str) -> ReadResult:
    if not os.path.exists(path):
        return ReadResult(ok=False, data={}, error="missing")
    try:
        with open(path, "r", encoding="utf-8") as f:
            obj = json.load(f)
        if not isinstance(obj, dict):
            return ReadResult(ok=False, data={}, error="not_object")
        return ReadResult(ok=True, data=obj)
    except json.JSONDecodeError as e:
        return ReadResult(ok=False, data={}, error=f"corrupt_json:{e}")
    except Exception as e:  # noqa: BLE001
        return ReadResult(ok=False, data={}, error=str(e))


def backup_file(path: str, backups_dir: str, *, reason: str, max_backups: int = 10) -> Optional[str]:
    if not os.path.exists(path):
        return None
    ensure_dirs(backups_dir)
    base = os.path.basename(path)
    out = os.path.join(backups_dir, f"{base}.{_ts()}.{reason}.json")
    try:
        shutil.copy2(path, out)
    except Exception:
        return None
    # retention per file
    try:
        prefix = f"{base}."
        items = [os.path.join(backups_dir, f) for f in os.listdir(backups_dir) if f.startswith(prefix)]
        items.sort(key=lambda p: os.path.getmtime(p), reverse=True)
        for p in items[max_backups:]:
            try:
                os.remove(p)
            except OSError:
                pass
    except Exception:
        pass
    return out


def atomic_write_json(path: str, data: Dict[str, Any], backups_dir: str, *, max_backups: int = 10) -> None:
    ensure_dirs(os.path.dirname(path), backups_dir)
    backup_file(path, backups_dir, reason="prewrite", max_backups=max_backups)
    fd, tmp = tempfile.mkstemp(prefix=".tmp_", suffix=".json", dir=os.path.dirname(path))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False, sort_keys=True)
            f.write("\n")
        os.replace(tmp, path)
    finally:
        try:
            if os.path.exists(tmp):
                os.remove(tmp)
        except OSError:
            pass


def recover_from_corrupt(path: str, backups_dir: str, last_known_good_dir: str, *, max_backups: int = 10) -> Tuple[Dict[str, Any], bool]:
    """
    On corrupt JSON:
    - move corrupt file to backups/<name>.<ts>.corrupt.json
    - try restore from last_known_good/<name>.json
    Returns (data, recovered)
    """
    ensure_dirs(backups_dir, last_known_good_dir)
    if os.path.exists(path):
        try:
            base = os.path.basename(path)
            corrupt_path = os.path.join(backups_dir, f"{base}.{_ts()}.corrupt.json")
            shutil.move(path, corrupt_path)
        except Exception:
            pass
    lkg_path = os.path.join(last_known_good_dir, os.path.basename(path))
    rr = read_json_file(lkg_path)
    if rr.ok:
        # restore last known good into place
        atomic_write_json(path, rr.data, backups_dir, max_backups=max_backups)
        return rr.data, True
    return {}, False


def snapshot_last_known_good(config_dir: str, last_known_good_dir: str) -> None:
    ensure_dirs(last_known_good_dir)
    for name in os.listdir(config_dir):
        if not name.endswith(".json"):
            continue
        src = os.path.join(config_dir, name)
        if not os.path.isfile(src):
            continue
        dst = os.path.join(last_known_good_dir, name)
        try:
            shutil.copy2(src, dst)
        except Exception:
            pass

