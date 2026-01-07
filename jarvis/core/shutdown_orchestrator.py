from __future__ import annotations

import os
import sys
import time
from dataclasses import dataclass
from enum import Enum
from typing import Any, Callable, Dict, Optional

from jarvis.core.ops_log import OpsLogger
from jarvis.core.events.models import BaseEvent, EventSeverity, SourceSubsystem


class ShutdownMode(str, Enum):
    GRACEFUL_STOP = "GRACEFUL_STOP"
    RESTART = "RESTART"


@dataclass
class ShutdownConfig:
    phase_timeouts_seconds: Dict[str, float]
    job_grace_seconds: float = 15.0
    force_kill_after_seconds: float = 30.0


class ShutdownOrchestrator:
    """
    Deterministic shutdown sequence with per-phase timeouts.
    """

    def __init__(
        self,
        *,
        cfg: ShutdownConfig,
        ops: OpsLogger,
        logger,
        runtime: Any,
        job_manager: Any = None,
        llm_lifecycle: Any = None,
        telemetry: Any = None,
        secure_store: Any = None,
        config_manager: Any = None,
        web_handle: Any = None,
        ui_handle: Any = None,
        exec_fn: Optional[Callable[[str, list[str]], None]] = None,
        root_path: str = ".",
    ):
        self.cfg = cfg
        self.ops = ops
        self.logger = logger
        self.runtime = runtime
        self.job_manager = job_manager
        self.llm_lifecycle = llm_lifecycle
        self.telemetry = telemetry
        self.secure_store = secure_store
        self.config_manager = config_manager
        self.web_handle = web_handle
        self.ui_handle = ui_handle
        self.runtime_state = None
        self.exec_fn = exec_fn or os.execv
        self.root_path = root_path
        self.event_bus = None

    def run_shutdown_sequence(self, *, mode: ShutdownMode, reason: str, trace_id: str, safe_mode: bool, argv: list[str], runtime_state=None, event_bus=None) -> None:
        self.runtime_state = runtime_state
        self.event_bus = event_bus
        self.ops.log(trace_id=trace_id, event="shutdown_begin", outcome="start", details={"mode": mode.value, "reason": reason, "safe_mode": safe_mode})
        if self.event_bus is not None:
            try:
                self.event_bus.publish_nowait(
                    BaseEvent(
                        event_type="shutdown.begin",
                        trace_id=trace_id,
                        source_subsystem=SourceSubsystem.recovery,
                        severity=EventSeverity.INFO,
                        payload={"mode": mode.value, "reason": reason},
                    )
                )
            except Exception:
                pass

        # Phase 0: announce/begin
        self._phase(trace_id, "phase0_begin", self._phase0_begin, timeout=2.0, details={"reason": reason})

        # Phase 1: quiesce inputs
        self._phase(trace_id, "quiesce_inputs", self._phase1_quiesce_inputs, timeout=self._to("quiesce_inputs", 5.0))

        # Phase 2: drain/cancel work
        self._phase(trace_id, "drain_jobs", self._phase2_drain_jobs, timeout=self._to("drain_jobs", 20.0))

        # Phase 3: persist & flush
        self._phase(trace_id, "persist_flush", self._phase3_persist_flush, timeout=self._to("persist_flush", 10.0))

        # Phase 4: unload heavy resources
        self._phase(trace_id, "unload_resources", self._phase4_unload_resources, timeout=self._to("unload_resources", 10.0))

        # Phase 5: stop services
        self._phase(trace_id, "stop_services", self._phase5_stop_services, timeout=self._to("stop_services", 10.0))

        # Phase 6: exit/restart
        self.ops.log(trace_id=trace_id, event="shutdown_complete", outcome="ok", details={"mode": mode.value})
        if self.event_bus is not None:
            try:
                self.event_bus.publish_nowait(
                    BaseEvent(
                        event_type="shutdown.complete",
                        trace_id=trace_id,
                        source_subsystem=SourceSubsystem.recovery,
                        severity=EventSeverity.INFO,
                        payload={"mode": mode.value},
                    )
                )
            except Exception:
                pass
        try:
            if self.runtime_state is not None:
                self.runtime_state.clear_dirty_shutdown(reason=reason)
                # Persist final crash/shutdown fields.
                self.runtime_state.save(reason="shutdown_complete")
        except Exception:
            pass

        if mode == ShutdownMode.RESTART:
            self.ops.log(trace_id=trace_id, event="restart_begin", outcome="ok", details={"argv": argv, "safe_mode": safe_mode})
            try:
                if self.runtime_state is not None:
                    self.runtime_state.write_restart_marker(argv=argv, safe_mode=safe_mode, trace_id=trace_id)
            except Exception:
                pass
            self.ops.log(trace_id=trace_id, event="restart_exec", outcome="exec", details={"python": sys.executable})
            self.exec_fn(sys.executable, [sys.executable, *argv[1:]])

    def _to(self, key: str, default: float) -> float:
        try:
            return float((self.cfg.phase_timeouts_seconds or {}).get(key, default))
        except Exception:
            return float(default)

    def _phase(self, trace_id: str, name: str, fn: Callable[[], None], *, timeout: float, details: Optional[Dict[str, Any]] = None) -> None:
        t0 = time.time()
        self.ops.log(trace_id=trace_id, event="shutdown_phase_start", outcome=name, details={"timeout": timeout, **(details or {})})
        if self.event_bus is not None:
            try:
                self.event_bus.publish_nowait(
                    BaseEvent(
                        event_type="shutdown.phase",
                        trace_id=trace_id,
                        source_subsystem=SourceSubsystem.recovery,
                        severity=EventSeverity.INFO,
                        payload={"phase": name, "status": "start"},
                    )
                )
            except Exception:
                pass
        ok = True
        err: Optional[str] = None

        # Run each phase with a hard timeout (best-effort). If it times out, continue and apply fallbacks.
        done = {"ok": False, "err": None}

        def run():
            try:
                fn()
                done["ok"] = True
            except Exception as e:  # noqa: BLE001
                done["ok"] = False
                done["err"] = str(e)

        import threading

        th = threading.Thread(target=run, name=f"shutdown-{name}", daemon=True)
        th.start()
        th.join(timeout=max(0.1, float(timeout)))
        if th.is_alive():
            ok = False
            err = "timeout"
            # Phase-specific fallback behavior
            try:
                if name == "drain_jobs" and self.job_manager is not None:
                    self.job_manager.stop()
                if name == "stop_services" and self.web_handle is not None:
                    self.web_handle.stop()
            except Exception:
                pass
        else:
            ok = bool(done["ok"])
            err = done["err"]

        dt = time.time() - t0
        if ok:
            self.ops.log(trace_id=trace_id, event="shutdown_phase_ok", outcome=name, details={"seconds": dt})
            if self.event_bus is not None:
                try:
                    self.event_bus.publish_nowait(
                        BaseEvent(
                            event_type="shutdown.phase",
                            trace_id=trace_id,
                            source_subsystem=SourceSubsystem.recovery,
                            severity=EventSeverity.INFO,
                            payload={"phase": name, "status": "ok", "seconds": dt},
                        )
                    )
                except Exception:
                    pass
        else:
            self.ops.log(trace_id=trace_id, event="shutdown_phase_fail", outcome=name, details={"seconds": dt, "error": err})
            if self.event_bus is not None:
                try:
                    self.event_bus.publish_nowait(
                        BaseEvent(
                            event_type="shutdown.phase",
                            trace_id=trace_id,
                            source_subsystem=SourceSubsystem.recovery,
                            severity=EventSeverity.WARN,
                            payload={"phase": name, "status": "fail", "seconds": dt, "error": err},
                        )
                    )
                except Exception:
                    pass

    # ---- phase methods ----
    def _phase0_begin(self) -> None:
        # Stop accepting inputs ASAP
        try:
            self.runtime.begin_shutdown(reason="shutdown")
        except Exception:
            pass
        # Block new secure store writes
        try:
            if self.secure_store is not None:
                self.secure_store.begin_shutdown()
        except Exception:
            pass
        # Web draining
        try:
            if self.web_handle is not None:
                self.web_handle.set_draining(True)
        except Exception:
            pass

    def _phase1_quiesce_inputs(self) -> None:
        # Voice already stopped by runtime.begin_shutdown; ensure wakeword stopped too
        try:
            if getattr(self.runtime, "voice_adapter", None) is not None:
                self.runtime.voice_adapter.stop()
        except Exception:
            pass
        # UI can show a banner (best effort)
        try:
            if self.ui_handle is not None:
                self.ui_handle.on_shutdown()
        except Exception:
            pass

    def _phase2_drain_jobs(self) -> None:
        if self.job_manager is None:
            return
        try:
            self.job_manager.begin_shutdown()
        except Exception:
            pass
        try:
            _ = self.job_manager.drain(grace_seconds=float(self.cfg.job_grace_seconds), force_kill_after_seconds=float(self.cfg.force_kill_after_seconds))
        except Exception:
            # last resort
            try:
                self.job_manager.stop()
            except Exception:
                pass

    def _phase3_persist_flush(self) -> None:
        # Persist runtime_state snapshot
        try:
            if self.runtime_state is not None:
                self.runtime_state.save(reason="shutdown")
        except Exception:
            pass
        # Flush telemetry thread (best effort)
        try:
            if self.telemetry is not None:
                # no explicit flush API; snapshot already written
                pass
        except Exception:
            pass

    def _phase4_unload_resources(self) -> None:
        # LLM unload
        try:
            if self.llm_lifecycle is not None:
                self.llm_lifecycle.unload_all("shutdown")
                self.llm_lifecycle.stop()
        except Exception:
            pass
        # Stop TTS thread
        try:
            if getattr(self.runtime, "tts_adapter", None) is not None:
                self.runtime.tts_adapter.stop()
        except Exception:
            pass

    def _phase5_stop_services(self) -> None:
        # Stop event bus last (drain prior events)
        try:
            if self.event_bus is not None:
                self.event_bus.shutdown(grace_seconds=float(self.cfg.phase_timeouts_seconds.get("stop_services", 5)))
        except Exception:
            pass
        # Web stop
        try:
            if self.web_handle is not None:
                self.web_handle.stop()
        except Exception:
            pass
        # Stop runtime
        try:
            self.runtime.request_shutdown()
        except Exception:
            pass
        try:
            self.runtime.stop()
        except Exception:
            pass
        # Stop jobs (if still running)
        try:
            if self.job_manager is not None:
                self.job_manager.stop()
        except Exception:
            pass
        # Stop telemetry
        try:
            if self.telemetry is not None:
                self.telemetry.stop()
        except Exception:
            pass

