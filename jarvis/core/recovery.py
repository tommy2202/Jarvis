from __future__ import annotations

import time
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, Optional, Tuple, Type

from pydantic import BaseModel, ConfigDict, Field

from jarvis.core.errors import (
    AdminRequiredError,
    ConfigError,
    JarvisError,
    LLMTimeoutError,
    LLMUnavailableError,
    PermissionDeniedError,
    STTError,
    TTSError,
    USBKeyMissingError,
)


class RecoveryAction(str, Enum):
    RETRY = "RETRY"
    FALLBACK = "FALLBACK"
    ABORT = "ABORT"
    SLEEP = "SLEEP"
    RESTART_SUBSYSTEM = "RESTART_SUBSYSTEM"


class RecoveryConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    debug: Dict[str, bool] = Field(default_factory=lambda: {"include_tracebacks": False, "log_prompts": False})
    retry: Dict[str, int] = Field(default_factory=lambda: {"llm_timeout_max_retries": 1, "llm_timeout_backoff_ms": 200})
    circuit_breakers: Dict[str, Dict[str, int]] = Field(default_factory=dict)


@dataclass
class Decision:
    action: RecoveryAction
    user_message: str
    retry_after_seconds: float = 0.0
    disable_subsystem: Optional[str] = None


class RecoveryPolicy:
    def __init__(self, cfg: RecoveryConfig):
        self.cfg = cfg

    def decide(self, err: JarvisError, *, subsystem: str) -> Decision:
        # Deterministic policy
        if isinstance(err, ConfigError):
            return Decision(RecoveryAction.ABORT, err.user_message)

        if isinstance(err, USBKeyMissingError):
            return Decision(RecoveryAction.FALLBACK, err.user_message)

        if isinstance(err, (PermissionDeniedError, AdminRequiredError)):
            return Decision(RecoveryAction.ABORT, err.user_message)

        if isinstance(err, LLMUnavailableError):
            return Decision(RecoveryAction.FALLBACK, err.user_message, disable_subsystem="llm")

        if isinstance(err, LLMTimeoutError):
            backoff = float(int(self.cfg.retry.get("llm_timeout_backoff_ms", 200)) / 1000.0)
            return Decision(RecoveryAction.RETRY, err.user_message, retry_after_seconds=backoff)

        if isinstance(err, STTError):
            return Decision(RecoveryAction.FALLBACK, err.user_message, disable_subsystem="stt")

        if isinstance(err, TTSError):
            # Continue text-only if TTS fails repeatedly
            return Decision(RecoveryAction.FALLBACK, err.user_message, disable_subsystem="tts")

        # default: recoverable errors -> fallback
        if err.recoverable:
            return Decision(RecoveryAction.FALLBACK, err.user_message)
        return Decision(RecoveryAction.ABORT, err.user_message)

