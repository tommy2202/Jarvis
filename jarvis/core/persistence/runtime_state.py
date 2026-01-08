from __future__ import annotations

import json
import os
import tempfile
import time
from typing import Any, Dict, Optional

from jarvis.core.events import redact


def snapshot_path(root: str = ".") -> str:
    return os.path.join(root, "logs", "runtime", "state_snapshot.json")


def dirty_flag_path(root: str = ".") -> str:
    return os.path.join(root, "logs", "runtime", "dirty_shutdown.flag")


def restart_marker_path(root: str = ".") -> str:
    return os.path.join(root, "logs", "runtime", "restart_marker.json")


def write_dirty_flag(root: str = ".", *, trace_id: str) -> None:
    os.makedirs(os.path.join(root, "logs", "runtime"), exist_ok=True)
    with open(dirty_flag_path(root), "w", encoding="utf-8") as f:
        f.write(f"{trace_id}\n")


def clear_dirty_flag(root: str = ".") -> None:
    try:
        os.remove(dirty_flag_path(root))
    except OSError:
        pass


def save_state_snapshot(root: str = ".", *, data: Dict[str, Any]) -> str:
    """
    Atomic write snapshot; never stores secrets (redacted).
    """
    path = snapshot_path(root)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    safe = {"ts": time.time(), **redact(data)}
    fd, tmp = tempfile.mkstemp(prefix=".tmp_state_", suffix=".json", dir=os.path.dirname(path))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(safe, f, indent=2, ensure_ascii=False, sort_keys=True)
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
    return path


def load_state_snapshot(root: str = ".") -> Optional[Dict[str, Any]]:
    path = snapshot_path(root)
    if not os.path.exists(path):
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            obj = json.load(f)
        return obj if isinstance(obj, dict) else None
    except Exception:
        return None


def write_restart_marker(root: str = ".", *, argv: list[str], safe_mode: bool, trace_id: str) -> str:
    path = restart_marker_path(root)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    payload = {"ts": time.time(), "trace_id": trace_id, "argv": list(argv), "safe_mode": bool(safe_mode)}
    fd, tmp = tempfile.mkstemp(prefix=".tmp_restart_", suffix=".json", dir=os.path.dirname(path))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2, ensure_ascii=False, sort_keys=True)
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
    return path


def consume_restart_marker(root: str = ".") -> Optional[Dict[str, Any]]:
    path = restart_marker_path(root)
    if not os.path.exists(path):
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            obj = json.load(f)
    except Exception:
        obj = None
    try:
        os.remove(path)
    except OSError:
        pass
    return obj if isinstance(obj, dict) else None

