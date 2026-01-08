from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, Optional

from jarvis.core.events import redact


class Severity(str, Enum):
    INFO = "INFO"
    WARN = "WARN"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


@dataclass
class JarvisError(Exception):
    code: str
    user_message: str
    severity: Severity = Severity.ERROR
    recoverable: bool = True
    context: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        super().__init__(self.code)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "code": self.code,
            "user_message": self.user_message,
            "severity": self.severity.value,
            "recoverable": bool(self.recoverable),
            "context": redact(self.context or {}),
        }


# ---- Core types ----
class ConfigError(JarvisError):
    def __init__(self, user_message: str = "Configuration error.", **ctx: Any):
        super().__init__("config_error", user_message, severity=Severity.CRITICAL, recoverable=False, context=ctx)


class SecureStoreError(JarvisError):
    def __init__(self, user_message: str = "Secure store error.", **ctx: Any):
        super().__init__("secure_store_error", user_message, severity=Severity.ERROR, recoverable=True, context=ctx)


class USBKeyMissingError(JarvisError):
    def __init__(self, user_message: str = "The USB key is required for secure features.", **ctx: Any):
        super().__init__("usb_key_missing", user_message, severity=Severity.WARN, recoverable=True, context=ctx)


class PermissionDeniedError(JarvisError):
    def __init__(self, user_message: str = "Permission denied.", **ctx: Any):
        super().__init__("permission_denied", user_message, severity=Severity.WARN, recoverable=False, context=ctx)


class AdminRequiredError(JarvisError):
    def __init__(self, user_message: str = "Admin required for this action.", **ctx: Any):
        super().__init__("admin_required", user_message, severity=Severity.WARN, recoverable=False, context=ctx)


class RateLimitError(JarvisError):
    def __init__(self, user_message: str = "Rate limit exceeded.", **ctx: Any):
        super().__init__("rate_limited", user_message, severity=Severity.WARN, recoverable=True, context=ctx)


class ValidationError(JarvisError):
    def __init__(self, user_message: str = "Invalid request.", **ctx: Any):
        super().__init__("validation_error", user_message, severity=Severity.WARN, recoverable=False, context=ctx)


class LLMUnavailableError(JarvisError):
    def __init__(self, user_message: str = "I’m unable to use the language model right now.", **ctx: Any):
        super().__init__("llm_unavailable", user_message, severity=Severity.WARN, recoverable=True, context=ctx)


class LLMTimeoutError(JarvisError):
    def __init__(self, user_message: str = "That’s taking too long.", **ctx: Any):
        super().__init__("llm_timeout", user_message, severity=Severity.WARN, recoverable=True, context=ctx)


class STTError(JarvisError):
    def __init__(self, user_message: str = "I’m having trouble with speech recognition right now.", **ctx: Any):
        super().__init__("stt_error", user_message, severity=Severity.WARN, recoverable=True, context=ctx)


class TTSError(JarvisError):
    def __init__(self, user_message: str = "I’m having trouble speaking right now.", **ctx: Any):
        super().__init__("tts_error", user_message, severity=Severity.ERROR, recoverable=True, context=ctx)


class WakeWordError(JarvisError):
    def __init__(self, user_message: str = "Wake word system error.", **ctx: Any):
        super().__init__("wake_word_error", user_message, severity=Severity.WARN, recoverable=True, context=ctx)


class JobError(JarvisError):
    def __init__(self, user_message: str = "Job failed.", **ctx: Any):
        super().__init__("job_error", user_message, severity=Severity.ERROR, recoverable=True, context=ctx)


class JobTimeoutError(JarvisError):
    def __init__(self, user_message: str = "Job timed out.", **ctx: Any):
        super().__init__("job_timeout", user_message, severity=Severity.ERROR, recoverable=True, context=ctx)


class StateTransitionError(JarvisError):
    def __init__(self, user_message: str = "Internal state error.", **ctx: Any):
        super().__init__("state_transition_error", user_message, severity=Severity.ERROR, recoverable=True, context=ctx)


class NetworkPolicyError(JarvisError):
    def __init__(self, user_message: str = "Network activity is not allowed.", **ctx: Any):
        super().__init__("network_policy_error", user_message, severity=Severity.WARN, recoverable=False, context=ctx)

