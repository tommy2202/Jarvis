from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any, Callable, Dict, Optional

from jarvis.core.telemetry.models import HealthCheckResult, HealthStatus, Subsystem
from jarvis.core.telemetry.redaction import telemetry_redact


@dataclass(frozen=True)
class CheckSpec:
    subsystem: Subsystem
    fn: Callable[[], HealthCheckResult]
    timeout_seconds: float = 1.0


def ok(subsystem: Subsystem, message: str, *, details: Optional[Dict[str, Any]] = None, latency_ms: Optional[float] = None, breaker: Optional[str] = None) -> HealthCheckResult:
    return HealthCheckResult(
        subsystem=subsystem,
        status=HealthStatus.OK,
        message=message,
        last_checked_at=time.time(),
        last_ok_at=time.time(),
        details=telemetry_redact(details or {}),
        latency_ms=latency_ms,
        circuit_breaker_state=breaker,
        remediation="",
    )


def degraded(subsystem: Subsystem, message: str, *, details: Optional[Dict[str, Any]] = None, latency_ms: Optional[float] = None, error_code: Optional[str] = None, breaker: Optional[str] = None, remediation: str = "") -> HealthCheckResult:
    return HealthCheckResult(
        subsystem=subsystem,
        status=HealthStatus.DEGRADED,
        message=message,
        last_checked_at=time.time(),
        last_ok_at=None,
        details=telemetry_redact(details or {}),
        latency_ms=latency_ms,
        error_code=error_code,
        circuit_breaker_state=breaker,
        remediation=remediation,
    )


def down(subsystem: Subsystem, message: str, *, details: Optional[Dict[str, Any]] = None, latency_ms: Optional[float] = None, error_code: Optional[str] = None, breaker: Optional[str] = None, remediation: str = "") -> HealthCheckResult:
    return HealthCheckResult(
        subsystem=subsystem,
        status=HealthStatus.DOWN,
        message=message,
        last_checked_at=time.time(),
        last_ok_at=None,
        details=telemetry_redact(details or {}),
        latency_ms=latency_ms,
        error_code=error_code,
        circuit_breaker_state=breaker,
        remediation=remediation,
    )


def unknown(subsystem: Subsystem, message: str, *, details: Optional[Dict[str, Any]] = None, latency_ms: Optional[float] = None) -> HealthCheckResult:
    return HealthCheckResult(
        subsystem=subsystem,
        status=HealthStatus.UNKNOWN,
        message=message,
        last_checked_at=time.time(),
        last_ok_at=None,
        details=telemetry_redact(details or {}),
        latency_ms=latency_ms,
        remediation="",
    )

