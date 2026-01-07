from __future__ import annotations

import sys
import threading
import time
import uuid
from dataclasses import dataclass
from typing import Any, Dict, Optional

import os

from jarvis.core.ops_log import OpsLogger
from jarvis.core.shutdown_orchestrator import ShutdownMode, ShutdownOrchestrator
from jarvis.core.runtime_state.io import RuntimeStatePaths, consume_restart_marker, dirty_exists


@dataclass
class ShutdownStatus:
    in_progress: bool = False
    mode: str = "none"
    reason: str = ""
    trace_id: str = ""
    started_at: float = 0.0
    last_error: Optional[str] = None


class RuntimeController:
    """
    Single entrypoint for shutdown/restart requests (CLI/UI/web).
    """

    def __init__(
        self,
        *,
        runtime_cfg: Dict[str, Any],
        ops: OpsLogger,
        logger,
        orchestrator: ShutdownOrchestrator,
        runtime_state: Any = None,
        security_manager: Any = None,
    ):
        self.runtime_cfg = runtime_cfg
        self.ops = ops
        self.logger = logger
        self.orchestrator = orchestrator
        self.runtime_state = runtime_state
        self.security_manager = security_manager
        self._lock = threading.Lock()
        self._status = ShutdownStatus()

    def get_shutdown_status(self) -> Dict[str, Any]:
        with self._lock:
            st = self._status
        return {
            "in_progress": st.in_progress,
            "mode": st.mode,
            "reason": st.reason,
            "trace_id": st.trace_id,
            "started_at": st.started_at,
            "last_error": st.last_error,
        }

    def request_shutdown(self, *, reason: str, restart: bool = False, safe_mode: bool = False, argv: Optional[list[str]] = None) -> None:
        trace_id = uuid.uuid4().hex
        mode = ShutdownMode.RESTART if restart else ShutdownMode.GRACEFUL_STOP
        with self._lock:
            if self._status.in_progress:
                return
            self._status = ShutdownStatus(in_progress=True, mode=mode.value, reason=reason, trace_id=trace_id, started_at=time.time())
        try:
            argv2 = argv or sys.argv
            self.orchestrator.run_shutdown_sequence(mode=mode, reason=reason, trace_id=trace_id, safe_mode=bool(safe_mode), argv=list(argv2), runtime_state=self.runtime_state, event_bus=getattr(self.orchestrator, "event_bus", None))
        except Exception as e:  # noqa: BLE001
            self.ops.log(trace_id=trace_id, event="shutdown_failed", outcome="error", details={"error": str(e)})
            with self._lock:
                self._status.last_error = str(e)
        finally:
            with self._lock:
                self._status.in_progress = False

    def request_restart(self, *, reason: str, safe_mode: bool = False, argv: Optional[list[str]] = None) -> None:
        self._enforce_restart_policy()
        self.request_shutdown(reason=reason, restart=True, safe_mode=safe_mode, argv=argv)

    def restart_subsystem(self, name: str) -> bool:
        """
        Best-effort subsystem restarts: llm|web|voice|jobs
        """
        name = str(name).lower()
        try:
            if name == "llm" and getattr(self.orchestrator, "llm_lifecycle", None) is not None:
                llm = self.orchestrator.llm_lifecycle
                llm.unload_all("restart_subsystem")
                # watchdog thread continues; ensure role ready is lazy
                return True
            if name == "web" and getattr(self.orchestrator, "web_handle", None) is not None:
                wh = self.orchestrator.web_handle
                wh.stop()
                wh.start()
                return True
            if name == "voice" and getattr(self.orchestrator, "runtime", None) is not None:
                rt = self.orchestrator.runtime
                rt.set_voice_enabled(False)
                rt.set_voice_enabled(True)
                return True
            if name == "jobs" and getattr(self.orchestrator, "job_manager", None) is not None:
                jm = self.orchestrator.job_manager
                if hasattr(jm, "restart_supervisor"):
                    jm.restart_supervisor()
                    return True
        except Exception:
            return False
        return False

    def _enforce_restart_policy(self) -> None:
        sd = (self.runtime_cfg or {}).get("shutdown") or {}
        if not bool(sd.get("enable_restart", True)):
            raise PermissionError("Restart disabled by config/runtime.json.")
        if bool(sd.get("restart_requires_admin", True)):
            if self.security_manager is None or not bool(self.security_manager.is_admin()):
                raise PermissionError("Admin required to restart.")


def check_startup_recovery(*, ops: OpsLogger, root_path: str = ".", runtime_dir: str = "runtime") -> Dict[str, Any]:
    """
    Called on startup:
    - detect dirty shutdown
    - detect restart marker and log restart_complete
    - always start with admin locked (handled elsewhere)
    """
    info: Dict[str, Any] = {"dirty_shutdown": False, "restart": None}
    paths = RuntimeStatePaths(runtime_dir=os.path.join(root_path, runtime_dir))  # type: ignore[name-defined]
    try:
        if dirty_exists(paths):
            info["dirty_shutdown"] = True
            ops.log(trace_id="startup", event="recovered_from_crash", outcome="dirty_flag_present", details={"runtime_dir": runtime_dir})
    except Exception:
        pass
    try:
        marker = consume_restart_marker(paths)
        if marker:
            info["restart"] = marker
            ops.log(trace_id=str(marker.get("trace_id") or "startup"), event="restart_complete", outcome="ok", details={"safe_mode": bool(marker.get("safe_mode"))})
    except Exception:
        pass
    return info

