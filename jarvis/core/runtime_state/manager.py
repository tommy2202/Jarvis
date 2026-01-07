from __future__ import annotations

import hashlib
import json
import os
import threading
import time
import uuid
from dataclasses import dataclass
from typing import Any, Dict, Optional

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from jarvis.core.events import redact
from jarvis.core.ops_log import OpsLogger
from jarvis.core.runtime_state.io import (
    RuntimeStatePaths,
    atomic_write_json,
    clear_dirty,
    consume_restart_marker,
    dirty_exists,
    ensure_dirs,
    mark_dirty,
    read_json,
    recover_from_corrupt,
    write_last_known_good,
    write_restart_marker,
)
from jarvis.core.runtime_state.migrations.migration_0001_initial import apply as mig_0001
from jarvis.core.runtime_state.models import BreakerSnapshot, LastErrorSnapshot, RuntimeState


class RuntimeStateManagerConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    enabled: bool = True
    state_version: int = Field(default=1, ge=1)
    backup_keep: int = Field(default=20, ge=1, le=200)
    write_interval_seconds: int = Field(default=10, ge=1, le=3600)
    write_on_events: list[str] = Field(default_factory=lambda: ["shutdown", "error", "breaker_change"])
    paths: Dict[str, Any] = Field(default_factory=lambda: {"runtime_dir": "runtime"})


class RuntimeStateManager:
    """
    Persistent operational runtime state (no secrets).
    Debounced writes + atomic backups + corruption recovery.
    """

    def __init__(self, *, cfg: RuntimeStateManagerConfig, ops: OpsLogger, logger=None):
        self.cfg = cfg
        self.ops = ops
        self.logger = logger
        self.paths = RuntimeStatePaths(runtime_dir=str((cfg.paths or {}).get("runtime_dir") or "runtime"))
        ensure_dirs(self.paths)

        self._lock = threading.Lock()
        self._state = RuntimeState()
        self._dirty = False
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._writer_loop, name="runtime-state-writer", daemon=True)
        self._deps: Dict[str, Any] = {}

        if self.cfg.enabled:
            self._thread.start()

    def attach(self, **deps: Any) -> None:
        with self._lock:
            self._deps.update(deps)

    # ---- lifecycle ----
    def load(self) -> RuntimeState:
        with self._lock:
            self._state = self._load_locked()
            return self._state

    def stop(self) -> None:
        self._stop.set()
        if self._thread.is_alive():
            self._thread.join(timeout=2.0)

    # ---- crash markers ----
    def mark_dirty_startup(self) -> None:
        was_dirty = dirty_exists(self.paths)
        tid = uuid.uuid4().hex
        mark_dirty(self.paths, tid)
        with self._lock:
            self._state.crash.last_startup_at = time.time()
            # admin always locked on disk
            self._state.security.admin_locked = True
            # if previous run was dirty, record note (this is for UI)
            if was_dirty:
                self._state.crash.dirty_shutdown_detected = True
                self._state.crash.recovered_from_crash_at = time.time()
        self.ops.log(trace_id="startup", event="runtime_state.dirty_marked", outcome="ok", details={})

    def clear_dirty_shutdown(self, reason: str) -> None:
        clear_dirty(self.paths)
        with self._lock:
            self._state.crash.last_shutdown_reason = str(reason)
            self._state.crash.last_shutdown_completed_at = time.time()
            self._state.security.admin_locked = True
        self.ops.log(trace_id="shutdown", event="runtime_state.dirty_cleared", outcome="ok", details={"reason": reason})

    # ---- recorders ----
    def record_transition(self, state_from: str, state_to: str, trace_id: str) -> None:
        with self._lock:
            self._state.state_machine.last_state = str(state_to)
            self._state.state_machine.last_trace_id = str(trace_id)
            self._state.state_machine.last_transition_at = time.time()
            self._dirty = True
        self._maybe_write("transition")

    def record_error(self, subsystem: str, jarvis_error: Any) -> None:
        code = getattr(jarvis_error, "code", "error")
        user_message = getattr(jarvis_error, "user_message", "Something went wrong.")
        with self._lock:
            self._state.errors_by_subsystem[str(subsystem)] = LastErrorSnapshot(ts=time.time(), code=str(code), user_message=str(user_message))
            self._dirty = True
        self._maybe_write("error")

    def record_breaker_state(self, subsystem: str, breaker_state: BreakerSnapshot) -> None:
        with self._lock:
            self._state.breakers[str(subsystem)] = breaker_state
            self._dirty = True
        self._maybe_write("breaker_change")

    def record_job_summary(self, *, last_job_id: Optional[str] = None, last_job_error: Optional[str] = None, queued: Optional[int] = None, running: Optional[int] = None) -> None:
        with self._lock:
            if last_job_id is not None:
                self._state.jobs.last_job_id = str(last_job_id)
            if last_job_error is not None:
                self._state.jobs.last_job_error = str(last_job_error)[:300]
            if queued is not None:
                self._state.jobs.queued = int(queued)
            if running is not None:
                self._state.jobs.running = int(running)
            self._dirty = True
        self._maybe_write("jobs")

    def set_lockouts_summary(self, summary: Dict[str, Any]) -> None:
        with self._lock:
            self._state.security.lockouts_summary = redact(summary or {})
            self._dirty = True

    # ---- snapshot/export ----
    def get_snapshot(self) -> Dict[str, Any]:
        with self._lock:
            st = self._state
        d = st.model_dump()
        # enforce hard rule: admin locked on disk
        d["security"]["admin_locked"] = True
        return d

    def export(self, path: str) -> None:
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(self.get_snapshot(), f, indent=2, ensure_ascii=False)

    # ---- restart marker ----
    def write_restart_marker(self, *, argv: list[str], safe_mode: bool, trace_id: str) -> None:
        payload = {"ts": time.time(), "trace_id": trace_id, "argv": list(argv), "safe_mode": bool(safe_mode)}
        write_restart_marker(self.paths, payload)

    def consume_restart_marker(self) -> Optional[Dict[str, Any]]:
        return consume_restart_marker(self.paths)

    def set_restart_marker_info(self, marker: Dict[str, Any]) -> None:
        with self._lock:
            self._state.crash.restart_marker = redact(marker or {})
            self._dirty = True

    # ---- persistence ----
    def save(self, reason: str) -> None:
        if not self.cfg.enabled:
            return
        with self._lock:
            self._update_from_deps_locked()
            self._state.updated_at = time.time()
            # hard rule
            self._state.security.admin_locked = True
            obj = self._state.model_dump()
            obj["security"]["admin_locked"] = True
            self._dirty = False
        atomic_write_json(self.paths.state_path, obj, backups_dir=self.paths.backups_dir, keep=int(self.cfg.backup_keep))
        write_last_known_good(self.paths)
        self.ops.log(trace_id="runtime", event="runtime_state.save", outcome="ok", details={"reason": reason})

    # ---- internals ----
    def _maybe_write(self, event_name: str) -> None:
        if not self.cfg.enabled:
            return
        if event_name in set(self.cfg.write_on_events or []):
            try:
                self.save(reason=event_name)
            except Exception:
                pass

    def _writer_loop(self) -> None:
        interval = max(1.0, float(self.cfg.write_interval_seconds))
        while not self._stop.is_set():
            time.sleep(interval)
            with self._lock:
                dirty = bool(self._dirty)
            if not dirty:
                continue
            try:
                self.save(reason="interval")
            except Exception:
                continue

    def _load_locked(self) -> RuntimeState:
        ok, data, err = read_json(self.paths.state_path)
        if not ok:
            if err and err.startswith("corrupt_json"):
                data = recover_from_corrupt(self.paths, keep=int(self.cfg.backup_keep))
            else:
                data = {}
        # migrations
        data, _changed = mig_0001(data)
        try:
            st = RuntimeState.model_validate(data)
        except ValidationError:
            # schema invalid -> recover and default
            data2 = recover_from_corrupt(self.paths, keep=int(self.cfg.backup_keep))
            try:
                st = RuntimeState.model_validate(mig_0001(data2)[0])
            except Exception:
                st = RuntimeState()
        # hard rule: never restore admin unlocked
        st.security.admin_locked = True
        # markers
        st.crash.dirty_shutdown_detected = dirty_exists(self.paths)
        return st

    def _update_from_deps_locked(self) -> None:
        deps = dict(self._deps)
        # config fingerprints
        cm = deps.get("config_manager")
        if cm is not None:
            try:
                cfg = cm.get()
                self._state.config.last_migrated_config_version = int(getattr(cfg.app, "config_version", 0) or 0)
                self._state.config.last_validated_at = time.time()
                # hash config files (non-sensitive)
                root = getattr(cm.fs, "config_dir", "config")
                files = {}
                for name in os.listdir(root):
                    if not name.endswith(".json"):
                        continue
                    p = os.path.join(root, name)
                    try:
                        b = open(p, "rb").read()
                        files[name] = hashlib.sha256(b).hexdigest()
                    except Exception:
                        continue
                self._state.config.files = files
            except Exception:
                pass
        # web info
        web = deps.get("web_info")
        if isinstance(web, dict):
            try:
                self._state.web = self._state.web.model_validate(web)  # type: ignore[assignment]
            except Exception:
                pass
        # telemetry summary (tiny)
        tm = deps.get("telemetry")
        if tm is not None:
            try:
                snap = tm.get_snapshot()
                h = snap.get("health") or []
                counts: Dict[str, int] = {"OK": 0, "DEGRADED": 0, "DOWN": 0, "UNKNOWN": 0}
                for r in h:
                    s = str(r.get("status") or "UNKNOWN")
                    counts[s] = int(counts.get(s, 0) + 1)
                res = snap.get("resources") or {}
                self._state.telemetry = self._state.telemetry.model_validate(  # type: ignore[union-attr]
                    {
                        "ts": time.time(),
                        "health_counts": counts,
                        "cpu_system_percent": res.get("cpu_system_percent"),
                        "ram_system_percent": res.get("ram_system_percent"),
                        "disk_logs_percent_used": res.get("disk_logs_percent_used"),
                    }
                )
            except Exception:
                pass

