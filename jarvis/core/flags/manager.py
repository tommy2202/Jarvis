from __future__ import annotations

import os
import threading
import time
from typing import Any, Dict, Optional

from jarvis.core.config.io import atomic_write_json, read_json_file
from jarvis.core.config.paths import ConfigFsPaths
from jarvis.core.errors import AdminRequiredError, PermissionDeniedError
from jarvis.core.events import redact
from jarvis.core.events.models import BaseEvent, EventSeverity, SourceSubsystem
from jarvis.core.security_events import SecurityAuditLogger
from jarvis.core.trace import resolve_trace_id


class FeatureFlagManager:
    def __init__(
        self,
        *,
        flags_path: Optional[str] = None,
        backups_dir: Optional[str] = None,
        logger=None,
        security_manager=None,
        audit_logger: Optional[SecurityAuditLogger] = None,
        event_bus: Any = None,
        read_only: bool = False,
        max_backups: int = 10,
    ):
        fs = ConfigFsPaths(".")
        self.flags_path = flags_path or os.path.join(fs.config_dir, "feature_flags.json")
        self.backups_dir = backups_dir or fs.backups_dir
        self.logger = logger
        self.security_manager = security_manager
        self.audit_logger = audit_logger or SecurityAuditLogger()
        self.event_bus = event_bus
        self.read_only = bool(read_only)
        self.max_backups = int(max_backups)
        self._lock = threading.Lock()

    def list_flags(self) -> Dict[str, bool]:
        with self._lock:
            raw = self._load_raw()
            flags = self._normalize_flags(raw.get("flags"))
        return {k: bool(v.get("enabled", False)) for k, v in flags.items()}

    def is_enabled(self, flag: str) -> bool:
        if not flag:
            return False
        with self._lock:
            raw = self._load_raw()
            flags = self._normalize_flags(raw.get("flags"))
        entry = flags.get(str(flag)) or {}
        return bool(entry.get("enabled", False))

    def set_flag(self, flag: str, enabled: bool, *, trace_id: Optional[str] = None, actor: str = "admin") -> bool:
        if not flag:
            raise ValueError("flag name required")
        if self.read_only:
            raise PermissionDeniedError("Feature flags are read-only.")
        if self.security_manager is not None and not bool(getattr(self.security_manager, "is_admin", lambda: False)()):
            raise AdminRequiredError("Admin required to modify feature flags.")
        trace_id = resolve_trace_id(trace_id)
        enabled = bool(enabled)
        with self._lock:
            raw = self._load_raw()
            flags = self._normalize_flags(raw.get("flags"))
            entry = dict(flags.get(str(flag)) or {"enabled": False})
            prev = bool(entry.get("enabled", False))
            entry["enabled"] = enabled
            entry["updated_at"] = _now_iso()
            entry["updated_by"] = actor
            flags[str(flag)] = entry
            raw["flags"] = flags
            raw["updated_at"] = entry["updated_at"]
            raw["updated_by"] = actor
            atomic_write_json(self.flags_path, raw, self.backups_dir, max_backups=self.max_backups)
        self._audit_change(trace_id=trace_id, flag=str(flag), enabled=enabled, previous=prev, actor=actor)
        return enabled

    # ---- internals ----
    def _load_raw(self) -> Dict[str, Any]:
        rr = read_json_file(self.flags_path)
        if rr.ok and isinstance(rr.data, dict):
            if not isinstance(rr.data.get("flags"), dict):
                rr.data["flags"] = {}
            return rr.data
        return self._bootstrap_defaults()

    def _bootstrap_defaults(self) -> Dict[str, Any]:
        data = self._read_template()
        if not isinstance(data, dict):
            data = {}
        flags = data.get("flags") if isinstance(data.get("flags"), dict) else {}
        flags = self._normalize_flags(flags, force_disabled=True)
        payload = {
            "flags": flags,
            "updated_at": str(data.get("updated_at") or "1970-01-01T00:00:00Z"),
            "updated_by": str(data.get("updated_by") or "system"),
        }
        if not self.read_only:
            try:
                atomic_write_json(self.flags_path, payload, self.backups_dir, max_backups=self.max_backups)
            except Exception as e:
                if self.logger:
                    self.logger.warning(f"Feature flags write failed: {e}")
        return payload

    def _read_template(self) -> Dict[str, Any]:
        template_path = os.path.join(os.path.dirname(__file__), "feature_flags.json")
        rr = read_json_file(template_path)
        if rr.ok and isinstance(rr.data, dict):
            return rr.data
        return {"flags": {}}

    def _normalize_flags(self, flags: Any, *, force_disabled: bool = False) -> Dict[str, Dict[str, Any]]:
        out: Dict[str, Dict[str, Any]] = {}
        if not isinstance(flags, dict):
            return out
        for name, entry in flags.items():
            if not name:
                continue
            out[str(name)] = self._normalize_entry(entry, force_disabled=force_disabled)
        return out

    @staticmethod
    def _normalize_entry(entry: Any, *, force_disabled: bool = False) -> Dict[str, Any]:
        enabled = False
        if isinstance(entry, dict):
            enabled = bool(entry.get("enabled", False))
            if force_disabled:
                enabled = False
            return {**entry, "enabled": enabled}
        if isinstance(entry, bool):
            enabled = bool(entry)
        if force_disabled:
            enabled = False
        return {"enabled": enabled}

    def _audit_change(self, *, trace_id: str, flag: str, enabled: bool, previous: bool, actor: str) -> None:
        try:
            self.audit_logger.log(
                trace_id=trace_id,
                severity="INFO",
                event="feature_flag.changed",
                ip=None,
                endpoint="flags",
                outcome="enabled" if enabled else "disabled",
                details={"flag": flag, "enabled": enabled, "previous": previous, "actor": actor},
            )
        except Exception:
            pass
        if self.event_bus is not None:
            try:
                self.event_bus.publish_nowait(
                    BaseEvent(
                        event_type="feature_flag.changed",
                        trace_id=trace_id,
                        source_subsystem=SourceSubsystem.dispatcher,
                        severity=EventSeverity.INFO,
                        payload=redact({"flag": flag, "enabled": enabled, "previous": previous, "actor": actor}),
                    )
                )
            except Exception:
                pass


def _now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
