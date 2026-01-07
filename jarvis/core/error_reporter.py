from __future__ import annotations

import json
import os
import threading
import time
import traceback
from dataclasses import dataclass
from typing import Any, Dict, Optional

from jarvis.core.events import redact
from jarvis.core.errors import (
    AdminRequiredError,
    ConfigError,
    JarvisError,
    LLMTimeoutError,
    LLMUnavailableError,
    PermissionDeniedError,
    RateLimitError,
    STTError,
    StateTransitionError,
    TTSError,
    USBKeyMissingError,
    ValidationError,
)


@dataclass
class ErrorReporterConfig:
    include_tracebacks: bool = False


class ErrorReporter:
    def __init__(self, *, path: str = os.path.join("logs", "errors.jsonl"), cfg: Optional[ErrorReporterConfig] = None, telemetry: Any = None, runtime_state: Any = None):
        self.path = path
        self.cfg = cfg or ErrorReporterConfig()
        self.telemetry = telemetry
        self.runtime_state = runtime_state
        self._lock = threading.Lock()
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        self._debug_override: Optional[bool] = None

    def set_debug_override(self, enabled: bool) -> None:
        self._debug_override = bool(enabled)

    def include_tracebacks(self) -> bool:
        if self._debug_override is not None:
            return bool(self._debug_override)
        return bool(self.cfg.include_tracebacks)

    def report_exception(self, exc: BaseException, *, trace_id: str, subsystem: str, context: Optional[Dict[str, Any]] = None) -> JarvisError:
        je = normalize_exception(exc, subsystem=subsystem, context=context or {})
        self.write_error(je, trace_id=trace_id, subsystem=subsystem, internal_exc=exc)
        return je

    def write_error(self, err: JarvisError, *, trace_id: str, subsystem: str, internal_exc: Optional[BaseException] = None) -> None:
        entry: Dict[str, Any] = {
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "trace_id": trace_id,
            "subsystem": subsystem,
            "error_code": err.code,
            "severity": err.severity.value,
            "recoverable": bool(err.recoverable),
            "user_message": err.user_message,
            "safe_context": redact(err.context or {}),
        }
        if self.include_tracebacks() and internal_exc is not None:
            entry["internal_context"] = {"traceback": traceback.format_exc(limit=30)}
        line = json.dumps(entry, ensure_ascii=False)
        with self._lock:
            with open(self.path, "a", encoding="utf-8") as f:
                f.write(line + "\n")
        # Passive telemetry signal (never throw)
        if self.telemetry is not None:
            try:
                self.telemetry.record_error(subsystem=subsystem, severity=entry.get("severity", "ERROR"), error_code=err.code, trace_id=trace_id)
            except Exception:
                pass
        if self.runtime_state is not None:
            try:
                self.runtime_state.record_error(subsystem=subsystem, jarvis_error=err)
            except Exception:
                pass

    def tail(self, n: int = 20) -> list[Dict[str, Any]]:
        if not os.path.exists(self.path):
            return []
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                lines = f.readlines()
            out = [json.loads(x) for x in lines[-max(1, int(n)) :]]
            return out
        except Exception:
            return []

    def by_trace_id(self, trace_id: str) -> list[Dict[str, Any]]:
        if not os.path.exists(self.path):
            return []
        out = []
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                for line in f:
                    try:
                        obj = json.loads(line)
                    except Exception:
                        continue
                    if obj.get("trace_id") == trace_id:
                        out.append(obj)
        except Exception:
            return []
        return out


def normalize_exception(exc: BaseException, *, subsystem: str, context: Dict[str, Any]) -> JarvisError:
    # Passthrough
    if isinstance(exc, JarvisError):
        return exc

    msg = str(exc)
    ctx = dict(context or {})

    # Map common exception types by subsystem hints
    if subsystem == "config":
        return ConfigError("Configuration error.", error=msg, **ctx)
    if subsystem in {"secure_store"}:
        return USBKeyMissingError() if "USB key" in msg or "key" in msg.lower() else SecureStoreErrorLike(msg, ctx)
    if subsystem == "llm":
        if "timeout" in msg.lower():
            return LLMTimeoutError()
        return LLMUnavailableError()
    if subsystem == "stt":
        return STTError()
    if subsystem == "tts":
        return TTSError()
    if subsystem == "state_machine":
        return StateTransitionError()

    # Generic safe error
    return JarvisError(code="unknown_error", user_message="Something went wrong.", context=ctx)


def SecureStoreErrorLike(msg: str, ctx: Dict[str, Any]) -> JarvisError:
    from jarvis.core.errors import SecureStoreError

    return SecureStoreError("Secure store error.", error=msg, **ctx)

