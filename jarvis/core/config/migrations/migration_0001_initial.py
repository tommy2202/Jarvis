from __future__ import annotations

from typing import Any, Dict, Tuple


def migrate(all_files: Dict[str, Dict[str, Any]]) -> Tuple[Dict[str, Dict[str, Any]], int]:
    """
    Migration 0001: introduce config/app.json v1 if missing.
    """
    out = dict(all_files)
    if "app.json" not in out:
        out["app.json"] = {
            "config_version": 1,
            "created_at": "1970-01-01T00:00:00Z",
            "last_migrated_at": "1970-01-01T00:00:00Z",
            "backups": {"max_backups_per_file": 10},
            "hot_reload": {"enabled": False, "debounce_ms": 500, "poll_interval_ms": 500},
        }
    return out, 1

