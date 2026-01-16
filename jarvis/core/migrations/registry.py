from __future__ import annotations

import os
import threading
import time
from typing import Any, Dict, Optional

from jarvis.core.config.io import atomic_write_json, read_json_file
from jarvis.core.config.paths import ConfigFsPaths


class VersionRegistry:
    def __init__(self, *, path: Optional[str] = None, backups_dir: Optional[str] = None, logger=None):
        fs = ConfigFsPaths(".")
        self.path = path or os.path.join(fs.config_dir, "schema_registry.json")
        self.backups_dir = backups_dir or fs.backups_dir
        self.logger = logger
        self._lock = threading.Lock()

    def is_applied(self, subsystem: str, migration_id: str) -> bool:
        data = self._load()
        entry = (data.get("subsystems") or {}).get(str(subsystem)) or {}
        applied = entry.get("applied") or {}
        return str(migration_id) in applied

    def record_applied(
        self,
        *,
        subsystem: str,
        migration_id: str,
        version: int,
        trace_id: str,
        details: Optional[Dict[str, Any]] = None,
    ) -> bool:
        with self._lock:
            data = self._load()
            subs = data.setdefault("subsystems", {})
            sub = subs.setdefault(str(subsystem), {"version": 0, "applied": {}})
            applied = sub.get("applied") or {}
            if str(migration_id) in applied:
                return False
            applied[str(migration_id)] = {
                "applied_at": _now_iso(),
                "version": int(version),
                "trace_id": str(trace_id or ""),
                "details": dict(details or {}),
            }
            sub["applied"] = applied
            sub["version"] = max(int(sub.get("version") or 0), int(version))
            subs[str(subsystem)] = sub
            data["subsystems"] = subs
            data["schema_version"] = int(data.get("schema_version") or 1)
            data["updated_at"] = _now_iso()
            data["updated_by"] = str(trace_id or "system")
            try:
                atomic_write_json(self.path, data, self.backups_dir, max_backups=10)
            except Exception as e:
                if self.logger:
                    self.logger.warning(f"Version registry write failed: {e}")
                raise
            return True

    def status(self) -> Dict[str, Any]:
        return self._load()

    # ---- internals ----
    def _load(self) -> Dict[str, Any]:
        rr = read_json_file(self.path)
        if rr.ok and isinstance(rr.data, dict):
            if not isinstance(rr.data.get("subsystems"), dict):
                rr.data["subsystems"] = {}
            rr.data.setdefault("schema_version", 1)
            rr.data.setdefault("updated_at", "1970-01-01T00:00:00Z")
            rr.data.setdefault("updated_by", "system")
            return rr.data
        return {"schema_version": 1, "updated_at": "1970-01-01T00:00:00Z", "updated_by": "system", "subsystems": {}}


def _now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
