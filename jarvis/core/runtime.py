from __future__ import annotations

import json
import os
import queue
import threading
import time
import traceback
import uuid
from concurrent.futures import Future, ThreadPoolExecutor, TimeoutError as FutureTimeout
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, Optional

from pydantic import BaseModel, Field

from jarvis.core.events import EventLogger, redact
from jarvis.core.error_reporter import ErrorReporter
from jarvis.core.errors import AdminRequiredError
from jarvis.core.recovery import RecoveryPolicy, RecoveryConfig
from jarvis.core.circuit_breaker import BreakerRegistry
from jarvis.core.events.models import BaseEvent, EventSeverity, SourceSubsystem


class StateTransitionError(RuntimeError):
    pass


class AssistantState(str, Enum):
    BOOTING = "BOOTING"
    SLEEPING = "SLEEPING"
    WAKE_DETECTED = "WAKE_DETECTED"
    LISTENING = "LISTENING"
    TRANSCRIBING = "TRANSCRIBING"
    UNDERSTANDING = "UNDERSTANDING"
    EXECUTING = "EXECUTING"
    RESPONDING = "RESPONDING"
    SPEAKING = "SPEAKING"
    IDLE = "IDLE"
    ERROR_RECOVERY = "ERROR_RECOVERY"


class EventType(str, Enum):
    # Voice
    WakeWordDetected = "WakeWordDetected"
    AudioCaptured = "AudioCaptured"
    TranscriptionReady = "TranscriptionReady"
    STTFailed = "STTFailed"
    # Text
    TextInputReceived = "TextInputReceived"
    AdminUnlockRequested = "AdminUnlockRequested"
    # Core pipeline
    RouteComplete = "RouteComplete"
    DispatchComplete = "DispatchComplete"
    ResponseReady = "ResponseReady"
    SpeakComplete = "SpeakComplete"
    # Control
    SleepRequested = "SleepRequested"
    ShutdownRequested = "ShutdownRequested"
    ErrorOccurred = "ErrorOccurred"
    TimeoutOccurred = "TimeoutOccurred"
    SayRequested = "SayRequested"


class RuntimeEvent(BaseModel):
    trace_id: str
    timestamp: float = Field(default_factory=lambda: time.time())
    source: str = Field(default="system")
    type: EventType
    payload: Dict[str, Any] = Field(default_factory=dict)


class RuntimeConfig(BaseModel):
    idle_sleep_seconds: float = 45.0
    timeouts: Dict[str, float] = Field(default_factory=dict)
    enable_voice: bool = False
    enable_tts: bool = True
    enable_wake_word: bool = True
    max_concurrent_interactions: int = 1
    busy_policy: str = "queue"  # queue|reject
    result_ttl_seconds: float = 120.0

    def timeout_for(self, state: AssistantState, default: float = 10.0) -> float:
        return float(self.timeouts.get(state.value, default))


@dataclass
class InteractionResult:
    trace_id: str
    reply: str
    intent: Dict[str, Any]
    created_at: float


class _JsonlWriter:
    def __init__(self, path: str):
        self.path = path
        self._lock = threading.Lock()
        os.makedirs(os.path.dirname(path), exist_ok=True)

    def write(self, obj: Dict[str, Any]) -> None:
        line = json.dumps(obj, ensure_ascii=False)
        with self._lock:
            with open(self.path, "a", encoding="utf-8") as f:
                f.write(line + "\n")


class JarvisRuntime:
    """
    Core assistant state machine:
    - Dedicated thread + event queue
    - Strict transitions + timeouts
    - One pipeline for CLI/web/voice
    - Result store: trace_id -> reply (TTL)
    """

    def __init__(
        self,
        *,
        cfg: RuntimeConfig,
        jarvis_app,  # JarvisApp (routing + dispatcher)
        event_logger: EventLogger,
        logger,
        job_manager: Any = None,
        llm_lifecycle: Any = None,
        voice_adapter: Any = None,
        tts_adapter: Any = None,
        security_manager: Any = None,
        secure_store: Any = None,
        telemetry: Any = None,
        runtime_state: Any = None,
        error_reporter: Optional[ErrorReporter] = None,
        recovery_policy: Optional[RecoveryPolicy] = None,
        breakers: Optional[BreakerRegistry] = None,
        persist_path: str = os.path.join("logs", "state_machine", "events.jsonl"),
        safe_mode: bool = False,
        event_bus: Any = None,
        audit_timeline: Any = None,
        module_manager: Any = None,
    ):
        self.cfg = cfg
        self.jarvis_app = jarvis_app
        self.event_logger = event_logger
        self.logger = logger
        self.job_manager = job_manager
        self.llm_lifecycle = llm_lifecycle
        self.voice_adapter = voice_adapter
        self.tts_adapter = tts_adapter
        self.security_manager = security_manager
        self.secure_store = secure_store
        self.telemetry = telemetry
        self.runtime_state = runtime_state
        self.error_reporter = error_reporter or ErrorReporter()
        self.recovery_policy = recovery_policy or RecoveryPolicy(RecoveryConfig())
        self.breakers = breakers or BreakerRegistry({})
        self.safe_mode = bool(safe_mode)
        self.event_bus = event_bus
        self.audit_timeline = audit_timeline
        self.module_manager = module_manager

        self._writer = _JsonlWriter(persist_path)
        self._q: "queue.Queue[RuntimeEvent]" = queue.Queue()
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, name="runtime", daemon=True)
        self._executor = ThreadPoolExecutor(max_workers=4, thread_name_prefix="runtime-worker")

        self._state = AssistantState.BOOTING
        self._state_entered_at = time.time()
        self._deadline: Optional[float] = None
        self._last_trace_id: Optional[str] = None
        self._llm_loaded = False

        self._accepting_inputs = True
        self._shutdown_in_progress = False

        self._voice_enabled = bool(cfg.enable_voice)
        self._wake_word_enabled = bool(cfg.enable_wake_word)

        self._busy_lock = threading.Lock()
        self._pending_interactions: "queue.Queue[RuntimeEvent]" = queue.Queue()

        self._results: Dict[str, InteractionResult] = {}
        self._results_lock = threading.Lock()

        self._set_state("boot", AssistantState.BOOTING, {})
        self._set_state("boot", AssistantState.SLEEPING, {})
        if self.telemetry is not None:
            try:
                self.telemetry.set_gauge("current_state_machine_state", self._state.value)
            except Exception:
                pass

    # ---------- Public control surface ----------
    def start(self) -> None:
        if self._thread.is_alive():
            return
        self._stop.clear()
        if self.voice_adapter is not None and self._voice_enabled:
            try:
                self.voice_adapter.start(on_wake=lambda: self._emit(EventType.WakeWordDetected, source="voice", payload={}))
            except Exception as e:
                self._log_sm("voice.start_failed", {"error": str(e)})
        self._thread.start()

    def begin_shutdown(self, *, reason: str = "shutdown") -> None:
        """
        Phase 0/1 hook: stop accepting new inputs and quiesce adapters.
        """
        self._shutdown_in_progress = True
        self._accepting_inputs = False
        try:
            if self.voice_adapter is not None:
                self.voice_adapter.stop()
        except Exception:
            pass
        self._log_sm("shutdown.begin", {"reason": reason})

    def stop(self) -> None:
        self.request_shutdown()
        self._thread.join(timeout=2.0)
        try:
            self._executor.shutdown(wait=False, cancel_futures=True)
        except Exception:
            pass
        if self.voice_adapter is not None:
            try:
                self.voice_adapter.stop()
            except Exception:
                pass
        if self.tts_adapter is not None:
            try:
                self.tts_adapter.stop()
            except Exception:
                pass

    def submit_text(self, source: str, text: str, client_meta: Optional[Dict[str, Any]] = None) -> str:
        trace_id = uuid.uuid4().hex
        if not self._accepting_inputs:
            # immediate safe reply
            with self._results_lock:
                self._results[trace_id] = InteractionResult(trace_id=trace_id, reply="Shutting down.", intent={"id": "system.shutdown", "source": "system", "confidence": 1.0}, created_at=time.time())
            return trace_id
        ev = RuntimeEvent(trace_id=trace_id, source=source, type=EventType.TextInputReceived, payload={"text": text, "client": redact(client_meta or {})})
        self._enqueue(ev)
        if self.telemetry is not None:
            try:
                self.telemetry.increment_counter("requests_total", 1, tags={"source": source})
            except Exception:
                pass
        return trace_id

    def request_listen(self, source: str = "ui") -> str:
        """
        Push-to-talk style: force a LISTENING capture once (uses the core voice adapter).
        """
        trace_id = uuid.uuid4().hex
        self._enqueue(RuntimeEvent(trace_id=trace_id, source=source, type=EventType.WakeWordDetected, payload={"push_to_talk": True}))
        return trace_id

    def request_sleep(self) -> None:
        self._emit(EventType.SleepRequested, source="system", payload={})

    def request_shutdown(self) -> None:
        self._emit(EventType.ShutdownRequested, source="system", payload={})

    def wake(self) -> str:
        trace_id = uuid.uuid4().hex
        self._enqueue(RuntimeEvent(trace_id=trace_id, source="system", type=EventType.WakeWordDetected, payload={"simulated": True}))
        return trace_id

    def say(self, text: str, source: str = "system") -> str:
        trace_id = uuid.uuid4().hex
        self._enqueue(RuntimeEvent(trace_id=trace_id, source=source, type=EventType.SayRequested, payload={"text": text}))
        return trace_id

    def get_status(self) -> Dict[str, Any]:
        admin = self.get_admin_status()
        secure = self.get_secure_store_status()
        llm = self.get_llm_status()
        voice = self.get_voice_status()
        rs = None
        if self.runtime_state is not None:
            try:
                rs = self.runtime_state.get_snapshot()
            except Exception:
                rs = None
        return {
            "state": self._state.value,
            "last_trace_id": self._last_trace_id,
            "state_entered_at": self._state_entered_at,
            "llm_loaded": self._llm_loaded,
            "queue_depth": self._q.qsize(),
            "pending_depth": self._pending_interactions.qsize(),
            "results_cached": len(self._results),
            "shutdown": {"in_progress": bool(self._shutdown_in_progress), "accepting_inputs": bool(self._accepting_inputs)},
            "admin": admin,
            "secure_store": secure,
            "llm": llm,
            "voice": voice,
            "audit": self.get_audit_status(),
            "modules": self.get_modules_status(),
            "runtime_state": rs,
            "runtime_cfg": {
                "max_concurrent_interactions": self.cfg.max_concurrent_interactions,
                "busy_policy": self.cfg.busy_policy,
            },
        }

    def get_modules_status(self) -> Dict[str, Any]:
        """
        Read-only module registry status for UI/web.
        """
        if self.module_manager is None:
            return {"enabled": False}
        try:
            raw = self.module_manager.list_registry()
            mods = raw.get("modules") if isinstance(raw, dict) else {}
            return {"enabled": True, "count": len(mods or {}), "modules": mods or {}}
        except Exception:
            return {"enabled": True, "error": "status_failed"}

    def modules_scan(self) -> Dict[str, Any]:
        if self.module_manager is None:
            return {"ok": False, "error": "unavailable"}
        return self.module_manager.scan(trace_id="runtime")

    def modules_enable(self, module_id: str) -> bool:
        if self.module_manager is None:
            return False
        if self.security_manager is not None and not bool(self.security_manager.is_admin()):
            raise AdminRequiredError()
        return bool(self.module_manager.enable(str(module_id), trace_id="runtime"))

    def modules_disable(self, module_id: str) -> bool:
        if self.module_manager is None:
            return False
        if self.security_manager is not None and not bool(self.security_manager.is_admin()):
            raise AdminRequiredError()
        return bool(self.module_manager.disable(str(module_id), trace_id="runtime"))

    def get_audit_status(self) -> Dict[str, Any]:
        if self.audit_timeline is None:
            return {"enabled": False}
        try:
            return {"enabled": True, "integrity_broken": bool(self.audit_timeline.integrity_broken())}
        except Exception:
            return {"enabled": True, "error": "status_failed"}

    def get_audit_tail(self, n: int = 30) -> list[str]:
        if self.audit_timeline is None:
            return []
        try:
            return self.audit_timeline.tail_formatted(n=int(n))
        except Exception:
            return []

    def audit_verify_integrity(self) -> Dict[str, Any]:
        if self.audit_timeline is None:
            return {"ok": True, "message": "audit disabled"}
        try:
            return self.audit_timeline.verify_integrity(limit_last_n=2000).model_dump()
        except Exception as e:
            return {"ok": False, "message": str(e)}

    def get_telemetry_snapshot(self) -> Optional[Dict[str, Any]]:
        if self.telemetry is None:
            return None
        try:
            return self.telemetry.get_snapshot()
        except Exception:
            return None

    def get_capabilities_snapshot(self) -> Optional[Dict[str, Any]]:
        """
        Read-only capability/policy introspection for UI/web.
        """
        try:
            eng = getattr(getattr(self.jarvis_app, "dispatcher", None), "capability_engine", None)
            if eng is None:
                return None
            return {"capabilities": eng.get_capabilities(), "intent_requirements": eng.get_intent_requirements(), "recent": eng.audit.recent(50)}
        except Exception:
            return None

    def get_health(self, subsystem: Optional[str] = None) -> list[Dict[str, Any]]:
        if self.telemetry is None:
            return []
        try:
            return self.telemetry.get_health(subsystem=subsystem)
        except Exception:
            return []

    def get_metrics_summary(self) -> Dict[str, Any]:
        if self.telemetry is None:
            return {}
        try:
            return self.telemetry.get_metrics_summary()
        except Exception:
            return {}

    def ui_heartbeat(self) -> None:
        if self.telemetry is None:
            return
        try:
            self.telemetry.ui_heartbeat()
        except Exception:
            pass

    def get_result(self, trace_id: str) -> Optional[Dict[str, Any]]:
        self._gc_results()
        with self._results_lock:
            r = self._results.get(trace_id)
            if not r:
                return None
            return {"trace_id": r.trace_id, "reply": r.reply, "intent": r.intent}

    def wait_for_result(self, trace_id: str, timeout_seconds: float = 20.0) -> Optional[Dict[str, Any]]:
        deadline = time.time() + float(timeout_seconds)
        while time.time() < deadline:
            r = self.get_result(trace_id)
            if r is not None:
                return r
            time.sleep(0.05)
        return None

    # ---------- Read-only APIs for UI/web ----------
    def get_admin_status(self) -> Dict[str, Any]:
        if self.security_manager is None:
            return {"available": False, "is_admin": False, "remaining_seconds": 0}
        try:
            is_admin = bool(self.security_manager.is_admin())
            remaining = 0
            try:
                sess = getattr(self.security_manager, "admin_session", None)
                if sess is not None and getattr(sess, "_unlocked", False):
                    last = float(getattr(sess, "_last_activity", 0.0))
                    timeout = float(getattr(sess, "timeout_seconds", 0.0))
                    remaining = max(0, int(timeout - (time.time() - last)))
            except Exception:
                remaining = 0
            return {"available": True, "is_admin": is_admin, "remaining_seconds": remaining}
        except Exception:
            return {"available": True, "is_admin": False, "remaining_seconds": 0}

    def admin_unlock(self, passphrase: str) -> bool:
        if self.security_manager is None:
            return False
        # Never log passphrase; do not include in events.
        ok = bool(self.security_manager.verify_and_unlock_admin(passphrase))
        if ok:
            self._log_sm("admin.unlocked", {})
        else:
            self._log_sm("admin.unlock_failed", {})
        return ok

    def admin_lock(self) -> None:
        if self.security_manager is None:
            return
        self.security_manager.lock_admin()
        self._log_sm("admin.locked", {})

    def get_secure_store_status(self) -> Dict[str, Any]:
        if self.secure_store is None:
            return {"available": False, "mode": "UNAVAILABLE", "status": "Secure store unavailable.", "next_steps": "Start Jarvis with secure store enabled."}
        try:
            return {"available": True, **(self.secure_store.export_public_status() or {})}
        except Exception as e:
            return {"available": True, "mode": "ERROR", "status": "Secure store status error.", "next_steps": "Check logs.", "last_error": str(e)}

    def get_llm_status(self) -> Dict[str, Any]:
        if self.llm_lifecycle is None:
            return {"enabled": False}
        try:
            return self.llm_lifecycle.get_status()
        except Exception:
            return {"enabled": True, "error": "status_failed"}

    def get_voice_status(self) -> Dict[str, Any]:
        return {
            "available": self.voice_adapter is not None,
            "voice_enabled": bool(self._voice_enabled),
            "wake_word_enabled": bool(self._wake_word_enabled),
            "tts_enabled": bool(self.cfg.enable_tts and self.tts_adapter is not None),
        }

    def set_voice_enabled(self, enabled: bool) -> None:
        enabled = bool(enabled)
        self._voice_enabled = enabled
        if self.voice_adapter is None:
            return
        if enabled:
            try:
                self.voice_adapter.start(on_wake=lambda: self._emit(EventType.WakeWordDetected, source="voice", payload={}))
                self._log_sm("voice.enabled", {})
            except Exception as e:
                self._log_sm("voice.enable_failed", {"error": str(e)})
        else:
            try:
                self.voice_adapter.stop()
                self._log_sm("voice.disabled", {})
            except Exception:
                pass

    def set_wake_word_enabled(self, enabled: bool) -> None:
        self._wake_word_enabled = bool(enabled)
        # Wake-word disabling is best-effort: we stop the wake engine if available.
        if self.voice_adapter is None:
            return
        try:
            we = getattr(self.voice_adapter, "wake_engine", None)
            if we is None:
                return
            if self._wake_word_enabled:
                we.start()
            else:
                we.stop()
            self._log_sm("wake_word.toggled", {"enabled": self._wake_word_enabled})
        except Exception as e:
            self._log_sm("wake_word.toggle_failed", {"error": str(e)})

    def get_jobs_summary(self, limit: int = 50) -> list[Dict[str, Any]]:
        if self.job_manager is None:
            return []
        try:
            jobs = self.job_manager.list_jobs()
        except Exception:
            return []
        out: list[Dict[str, Any]] = []
        for j in jobs[: max(1, int(limit))]:
            try:
                out.append(
                    {
                        "id": str(j.id),
                        "kind": str(j.kind),
                        "status": str(j.status.value if hasattr(j.status, "value") else j.status),
                        "progress": int(getattr(j, "progress", 0)),
                        "message": str(getattr(j, "message", "") or ""),
                        "trace_id": str(getattr(j, "trace_id", "") or ""),
                    }
                )
            except Exception:
                continue
        return out

    def cancel_job(self, job_id: str) -> bool:
        if self.job_manager is None:
            return False
        if self.security_manager is not None and not bool(self.security_manager.is_admin()):
            raise AdminRequiredError()
        return bool(self.job_manager.cancel_job(job_id))

    def get_recent_errors(self, n: int = 50) -> list[Dict[str, Any]]:
        try:
            return self.error_reporter.tail(int(n))
        except Exception:
            return []

    def get_recent_security_events(self, n: int = 50) -> list[Dict[str, Any]]:
        return _tail_jsonl(os.path.join("logs", "security.jsonl"), n=int(n))

    def get_recent_system_logs(self, n: int = 200) -> list[str]:
        return _tail_text(os.path.join("logs", "jarvis.log"), n=int(n))

    # ---------- Internal queueing ----------
    def _emit(self, typ: EventType, *, source: str, payload: Dict[str, Any], trace_id: Optional[str] = None) -> None:
        tid = trace_id or uuid.uuid4().hex
        self._enqueue(RuntimeEvent(trace_id=tid, source=source, type=typ, payload=redact(payload)))

    def _enqueue(self, ev: RuntimeEvent) -> None:
        self._writer.write({"ts": ev.timestamp, "trace_id": ev.trace_id, "event": ev.type.value, "source": ev.source, "payload": ev.payload})
        self._q.put(ev)

    def _log_sm(self, name: str, details: Dict[str, Any]) -> None:
        self._writer.write({"ts": time.time(), "trace_id": self._last_trace_id or "sm", "event": name, "details": redact(details)})

    # ---------- State management ----------
    def _set_state(self, trace_id: str, new_state: AssistantState, details: Dict[str, Any]) -> None:
        old = self._state
        allowed = self._allowed_transitions().get(old, set())
        if new_state != old and new_state not in allowed:
            raise StateTransitionError(f"Invalid transition {old.value} -> {new_state.value}")
        self._state = new_state
        self._state_entered_at = time.time()
        self._deadline = self._state_entered_at + self.cfg.timeout_for(new_state, default=9999.0)
        self._last_trace_id = trace_id
        self._writer.write(
            {
                "ts": self._state_entered_at,
                "trace_id": trace_id,
                "event": "state.transition",
                "from": old.value,
                "to": new_state.value,
                "details": redact(details),
            }
        )
        self.event_logger.log(trace_id, "core.state", {"from": old.value, "to": new_state.value, **redact(details)})
        if self.telemetry is not None:
            try:
                self.telemetry.set_gauge("current_state_machine_state", new_state.value)
            except Exception:
                pass
        if self.runtime_state is not None:
            try:
                self.runtime_state.record_transition(old.value, new_state.value, trace_id)
            except Exception:
                pass
        if self.event_bus is not None:
            try:
                self.event_bus.publish_nowait(
                    BaseEvent(
                        event_type="state.transition",
                        trace_id=trace_id,
                        source_subsystem=SourceSubsystem.state_machine,
                        severity=EventSeverity.INFO,
                        payload={"from": old.value, "to": new_state.value},
                    )
                )
            except Exception:
                pass

    def _allowed_transitions(self) -> Dict[AssistantState, set[AssistantState]]:
        return {
            AssistantState.BOOTING: {AssistantState.SLEEPING, AssistantState.ERROR_RECOVERY},
            AssistantState.SLEEPING: {AssistantState.WAKE_DETECTED, AssistantState.UNDERSTANDING, AssistantState.ERROR_RECOVERY},
            AssistantState.WAKE_DETECTED: {AssistantState.LISTENING, AssistantState.UNDERSTANDING, AssistantState.ERROR_RECOVERY},
            AssistantState.LISTENING: {AssistantState.TRANSCRIBING, AssistantState.UNDERSTANDING, AssistantState.ERROR_RECOVERY, AssistantState.SLEEPING},
            AssistantState.TRANSCRIBING: {AssistantState.UNDERSTANDING, AssistantState.ERROR_RECOVERY, AssistantState.SLEEPING},
            AssistantState.UNDERSTANDING: {AssistantState.EXECUTING, AssistantState.RESPONDING, AssistantState.ERROR_RECOVERY},
            AssistantState.EXECUTING: {AssistantState.RESPONDING, AssistantState.ERROR_RECOVERY},
            AssistantState.RESPONDING: {AssistantState.SPEAKING, AssistantState.IDLE, AssistantState.ERROR_RECOVERY},
            AssistantState.SPEAKING: {AssistantState.IDLE, AssistantState.ERROR_RECOVERY},
            AssistantState.IDLE: {AssistantState.SLEEPING, AssistantState.UNDERSTANDING, AssistantState.ERROR_RECOVERY},
            AssistantState.ERROR_RECOVERY: {AssistantState.SLEEPING},
        }

    def _ensure_llm_loaded(self, trace_id: str) -> None:
        if self._llm_loaded:
            return
        # Circuit breaker gate for LLM
        br = self.breakers.breakers.get("llm") if hasattr(self.breakers, "breakers") else None
        if br is not None and not br.allow():
            raise RuntimeError("llm breaker open")
        try:
            if self.llm_lifecycle is not None:
                self.llm_lifecycle.ensure_role_ready("chat", trace_id=trace_id)
            else:
                self.jarvis_app.stage_b.warmup()
            if br is not None:
                br.record_success()
        except Exception:
            if br is not None:
                br.record_failure()
            pass
        self._llm_loaded = True
        self._log_sm("llm.loaded", {})
        if self.telemetry is not None:
            try:
                self.telemetry.set_gauge("llm_loaded", 1, tags={"role": "chat"})
            except Exception:
                pass

    def _unload_llm(self, trace_id: str) -> None:
        if not self._llm_loaded:
            return
        # If job manager exists, schedule as a job for observability; otherwise do it directly.
        if self.job_manager is not None and "system.sleep_llm" in getattr(self.job_manager, "allowed_kinds", lambda: [])():
            try:
                self.job_manager.submit_job("system.sleep_llm", {}, {"source": "system", "client_id": "runtime"}, priority=5, max_runtime_seconds=30)
                self._llm_loaded = False
                self._log_sm("llm.unload_scheduled", {})
                return
            except Exception:
                pass
        try:
            if self.llm_lifecycle is not None:
                self.llm_lifecycle.unload_role("chat", reason="idle", trace_id=trace_id)
            else:
                self.jarvis_app.stage_b.unload()
        except Exception:
            pass
        self._llm_loaded = False
        self._log_sm("llm.unloaded", {})
        if self.telemetry is not None:
            try:
                self.telemetry.set_gauge("llm_loaded", 0, tags={"role": "chat"})
            except Exception:
                pass

    # ---------- Runtime loop ----------
    def _run(self) -> None:
        while not self._stop.is_set():
            self._gc_results()
            # State timeout enforcement
            if self._deadline is not None and time.time() > self._deadline:
                self._enqueue(
                    RuntimeEvent(
                        trace_id=self._last_trace_id or uuid.uuid4().hex,
                        source="system",
                        type=EventType.TimeoutOccurred,
                        payload={"state": self._state.value},
                    )
                )
                # avoid spinning
                self._deadline = time.time() + 9999.0

            try:
                ev = self._q.get(timeout=0.1)
            except queue.Empty:
                # If IDLE and idle window passed -> sleep.
                if self._state == AssistantState.IDLE and (time.time() - self._state_entered_at) >= float(self.cfg.idle_sleep_seconds):
                    self._emit(EventType.SleepRequested, source="system", payload={}, trace_id=self._last_trace_id)
                continue

            try:
                self._handle_event(ev)
            except StateTransitionError as e:
                je = self.error_reporter.report_exception(e, trace_id=ev.trace_id, subsystem="state_machine", context={"transition_invalid": True})
                _ = self.recovery_policy.decide(je, subsystem="state_machine")
                self._recover(ev.trace_id, "state_transition_error")
            except Exception as e:  # noqa: BLE001
                je = self.error_reporter.report_exception(e, trace_id=ev.trace_id, subsystem="state_machine", context={"event": ev.type.value, "state": self._state.value})
                decision = self.recovery_policy.decide(je, subsystem="state_machine")
                # Always produce a user-facing reply for interactive inputs.
                if ev.type in {EventType.TextInputReceived, EventType.WakeWordDetected, EventType.AudioCaptured, EventType.STTFailed}:
                    try:
                        self._finalize_reply(ev.trace_id, decision.user_message, intent={"id": "system.error", "source": "system", "confidence": 1.0})
                    except Exception:
                        pass
                self._recover(ev.trace_id, je.code)

    def _recover(self, trace_id: str, reason: str) -> None:
        try:
            # Force ERROR_RECOVERY then SLEEPING
            self._state = AssistantState.ERROR_RECOVERY
            self._writer.write({"ts": time.time(), "trace_id": trace_id, "event": "state.forced", "to": "ERROR_RECOVERY", "reason": reason})
            self._set_state(trace_id, AssistantState.SLEEPING, {"recovered_from": reason})
        except Exception:
            # last resort: reset
            self._state = AssistantState.SLEEPING

    def _gc_results(self) -> None:
        ttl = float(self.cfg.result_ttl_seconds)
        cutoff = time.time() - ttl
        with self._results_lock:
            for k in list(self._results.keys()):
                if self._results[k].created_at < cutoff:
                    self._results.pop(k, None)

    # ---------- Event handling ----------
    def _handle_event(self, ev: RuntimeEvent) -> None:
        self._writer.write({"ts": time.time(), "trace_id": ev.trace_id, "event": "event.process", "type": ev.type.value, "state": self._state.value})

        if self._shutdown_in_progress and ev.type in {EventType.TextInputReceived, EventType.WakeWordDetected}:
            # Drain mode: do not start new interactions
            self._finalize_reply(ev.trace_id, "Shutting down.", intent={"id": "system.shutdown", "source": "system", "confidence": 1.0})
            return

        if ev.type == EventType.ShutdownRequested:
            self._stop.set()
            try:
                if self.voice_adapter is not None:
                    self.voice_adapter.stop()
            except Exception:
                pass
            return

        if ev.type == EventType.SleepRequested:
            # Always allowed: unload LLM and return to SLEEPING
            self._unload_llm(ev.trace_id)
            if self._state != AssistantState.SLEEPING:
                # force via ERROR_RECOVERY if needed
                self._state = AssistantState.ERROR_RECOVERY
                self._set_state(ev.trace_id, AssistantState.SLEEPING, {"sleep_requested": True})
            return

        if ev.type == EventType.SayRequested:
            self._ensure_llm_loaded(ev.trace_id)  # keep consistent: "awake" interaction
            self._set_state(ev.trace_id, AssistantState.RESPONDING, {"say": True})
            reply = str(ev.payload.get("text") or "")
            self._finalize_reply(ev.trace_id, reply, intent={"id": "system.say", "source": "system", "confidence": 1.0})
            return

        # Busy policy: only one active interaction at a time.
        if self._state not in {AssistantState.SLEEPING, AssistantState.IDLE} and ev.type in {EventType.TextInputReceived, EventType.WakeWordDetected}:
            if self.cfg.busy_policy == "reject":
                self._finalize_reply(ev.trace_id, "I’m busy right now.", intent={"id": "system.busy", "source": "system", "confidence": 1.0})
                return
            self._pending_interactions.put(ev)
            return

        if ev.type == EventType.TimeoutOccurred:
            st = str(ev.payload.get("state") or "")
            # fail-safe: speak a generic error (if possible) and sleep
            self._finalize_reply(ev.trace_id, "That’s taking too long.", intent={"id": "system.timeout", "source": "system", "confidence": 1.0})
            self._set_state(ev.trace_id, AssistantState.IDLE, {"timeout_state": st})
            return

        if ev.type == EventType.WakeWordDetected:
            self._ensure_llm_loaded(ev.trace_id)
            self._set_state(ev.trace_id, AssistantState.WAKE_DETECTED, {"source": ev.source})
            if self._voice_enabled and self.voice_adapter is not None:
                self._set_state(ev.trace_id, AssistantState.LISTENING, {})
                self._start_voice_listen(ev.trace_id)
            else:
                # No voice: treat wake as "ready for text"
                self._set_state(ev.trace_id, AssistantState.IDLE, {"wake_no_voice": True})
            return

        if ev.type == EventType.AudioCaptured:
            self._set_state(ev.trace_id, AssistantState.TRANSCRIBING, {"path": ev.payload.get("path")})
            self._start_transcribe(ev.trace_id, str(ev.payload.get("path") or ""))
            return

        if ev.type == EventType.TranscriptionReady:
            text = str(ev.payload.get("text") or "").strip()
            self._enqueue(RuntimeEvent(trace_id=ev.trace_id, source="voice", type=EventType.TextInputReceived, payload={"text": text, "client": {"name": "voice"}}))
            return

        if ev.type == EventType.STTFailed:
            self._finalize_reply(ev.trace_id, "I didn’t catch that.", intent={"id": "system.stt_failed", "source": "voice", "confidence": 1.0})
            self._set_state(ev.trace_id, AssistantState.IDLE, {"stt_failed": True})
            return

        if ev.type == EventType.TextInputReceived:
            self._ensure_llm_loaded(ev.trace_id)
            # UNDERSTANDING (route)
            self._set_state(ev.trace_id, AssistantState.UNDERSTANDING, {"source": ev.source})
            text = str(ev.payload.get("text") or "")
            client = ev.payload.get("client") or {}
            # run pipeline synchronously in this thread (fast) to keep determinism
            try:
                resp = self.jarvis_app.process_message(text, client=client, source=str(ev.source), safe_mode=self.safe_mode, shutting_down=bool(self._shutdown_in_progress))
            except TypeError:
                # Backward-compatible for test fakes / older JarvisApp signatures
                resp = self.jarvis_app.process_message(text, client=client)
            self._writer.write({"ts": time.time(), "trace_id": resp.trace_id, "event": "route.complete", "intent_id": resp.intent_id, "source": resp.intent_source, "confidence": resp.confidence})
            # EXECUTING happens inside jarvis_app.dispatcher; but we still represent it explicitly.
            self._set_state(ev.trace_id, AssistantState.EXECUTING, {"intent_id": resp.intent_id})
            self._set_state(ev.trace_id, AssistantState.RESPONDING, {"intent_id": resp.intent_id})
            self._finalize_reply(
                ev.trace_id,
                resp.reply,
                intent={"id": resp.intent_id, "source": resp.intent_source, "confidence": resp.confidence},
                modifications=getattr(resp, "modifications", {}) or {},
            )
            return

        if ev.type == EventType.SpeakComplete:
            self._set_state(ev.trace_id, AssistantState.IDLE, {})
            self._maybe_dequeue_next()
            return

    def _maybe_dequeue_next(self) -> None:
        try:
            nxt = self._pending_interactions.get_nowait()
        except queue.Empty:
            return
        self._q.put(nxt)

    def _finalize_reply(self, trace_id: str, reply: str, intent: Dict[str, Any], *, modifications: Dict[str, Any] | None = None) -> None:
        reply = str(reply or "")
        with self._results_lock:
            self._results[trace_id] = InteractionResult(trace_id=trace_id, reply=reply, intent=redact(intent), created_at=time.time())
        self._writer.write({"ts": time.time(), "trace_id": trace_id, "event": "response.ready", "reply_len": len(reply), "intent": redact(intent)})
        self.event_logger.log(trace_id, "core.reply", {"reply_len": len(reply), "intent": intent})

        tts_allowed = True
        try:
            flags = (modifications or {}).get("flags") if isinstance(modifications, dict) else None
            if isinstance(flags, dict) and flags.get("tts_enabled") is False:
                tts_allowed = False
        except Exception:
            tts_allowed = True

        if self.cfg.enable_tts and self.tts_adapter is not None and tts_allowed:
            self._set_state(trace_id, AssistantState.SPEAKING, {})
            self._start_speaking(trace_id, reply)
        else:
            self._set_state(trace_id, AssistantState.IDLE, {})
            self._maybe_dequeue_next()

    def _start_speaking(self, trace_id: str, text: str) -> None:
        def run():
            t0 = time.time()
            try:
                br = self.breakers.breakers.get("tts") if hasattr(self.breakers, "breakers") else None
                if br is not None and not br.allow():
                    raise RuntimeError("tts breaker open")
                self.tts_adapter.speak(trace_id, text)
                if br is not None:
                    br.record_success()
            except Exception as e:
                if br is not None:
                    br.record_failure()
                self.error_reporter.report_exception(e, trace_id=trace_id, subsystem="tts", context={})
            finally:
                if self.telemetry is not None:
                    try:
                        self.telemetry.record_latency("tts_latency_ms", (time.time() - t0) * 1000.0)
                    except Exception:
                        pass
                self._enqueue(RuntimeEvent(trace_id=trace_id, source="system", type=EventType.SpeakComplete, payload={}))

        self._executor.submit(run)

    def _start_voice_listen(self, trace_id: str) -> None:
        # Use adapter to capture audio and emit AudioCaptured / Timeout
        listen_seconds = float(getattr(self.voice_adapter, "listen_seconds", self.cfg.timeout_for(AssistantState.LISTENING, 8)))

        def run():
            try:
                path = self.voice_adapter.capture_audio(trace_id)
                self._enqueue(RuntimeEvent(trace_id=trace_id, source="voice", type=EventType.AudioCaptured, payload={"path": path}))
            except Exception as e:
                self._enqueue(RuntimeEvent(trace_id=trace_id, source="voice", type=EventType.STTFailed, payload={"error": str(e)}))

        self._executor.submit(run)

    def _start_transcribe(self, trace_id: str, wav_path: str) -> None:
        def run():
            t0 = time.time()
            try:
                br = self.breakers.breakers.get("stt") if hasattr(self.breakers, "breakers") else None
                if br is not None and not br.allow():
                    raise RuntimeError("stt breaker open")
                text = self.voice_adapter.transcribe(wav_path)
                if not text.strip():
                    raise RuntimeError("empty transcription")
                if br is not None:
                    br.record_success()
                self._enqueue(RuntimeEvent(trace_id=trace_id, source="voice", type=EventType.TranscriptionReady, payload={"text": text}))
            except Exception as e:
                if br is not None:
                    br.record_failure()
                self.error_reporter.report_exception(e, trace_id=trace_id, subsystem="stt", context={})
                self._enqueue(RuntimeEvent(trace_id=trace_id, source="voice", type=EventType.STTFailed, payload={"error": str(e)}))
            finally:
                if self.telemetry is not None:
                    try:
                        self.telemetry.record_latency("stt_latency_ms", (time.time() - t0) * 1000.0)
                    except Exception:
                        pass

        self._executor.submit(run)


def _tail_jsonl(path: str, *, n: int) -> list[Dict[str, Any]]:
    if not os.path.exists(path):
        return []
    try:
        with open(path, "r", encoding="utf-8") as f:
            lines = f.readlines()
        out: list[Dict[str, Any]] = []
        for line in lines[-max(1, int(n)) :]:
            try:
                obj = json.loads(line)
            except Exception:
                continue
            if isinstance(obj, dict):
                out.append(obj)
        return out
    except Exception:
        return []


def _tail_text(path: str, *, n: int) -> list[str]:
    if not os.path.exists(path):
        return []
    try:
        with open(path, "r", encoding="utf-8") as f:
            lines = f.readlines()
        return [x.rstrip("\n") for x in lines[-max(1, int(n)) :]]
    except Exception:
        return []


# ---------- Optional adapters implemented using existing voice package ----------
class VoiceAdapter:
    def __init__(self, *, recorder, stt_primary, stt_fallback=None, wake_engine=None, listen_seconds: float = 8.0):
        self.recorder = recorder
        self.stt_primary = stt_primary
        self.stt_fallback = stt_fallback
        self.wake_engine = wake_engine
        self.listen_seconds = float(listen_seconds)
        self._on_wake = None

    def start(self, on_wake) -> None:  # noqa: ANN001
        self._on_wake = on_wake
        if self.wake_engine is not None:
            # Ensure engine calls our callback.
            try:
                self.wake_engine.on_wake = on_wake  # type: ignore[attr-defined]
            except Exception:
                pass
            self.wake_engine.start()

    def stop(self) -> None:
        if self.wake_engine is not None:
            self.wake_engine.stop()

    def capture_audio(self, trace_id: str) -> str:
        return self.recorder.record_wav(trace_id, seconds=self.listen_seconds)

    def transcribe(self, wav_path: str) -> str:
        try:
            return self.stt_primary.transcribe(wav_path)
        except Exception:
            if self.stt_fallback is None:
                raise
            return self.stt_fallback.transcribe(wav_path)


class TTSAdapter:
    def __init__(self, *, worker):
        self.worker = worker

    def speak(self, trace_id: str, text: str) -> None:
        self.worker.speak_blocking(trace_id, text)

    def stop(self) -> None:
        try:
            self.worker.stop()
        except Exception:
            pass

