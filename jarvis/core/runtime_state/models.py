from __future__ import annotations

import time
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field


class BreakerSnapshot(BaseModel):
    model_config = ConfigDict(extra="forbid")
    state: str = "UNKNOWN"  # CLOSED|OPEN|HALF_OPEN|UNKNOWN
    opened_at: Optional[float] = None
    cooldown_until: Optional[float] = None
    failure_count_window: int = 0


class LastErrorSnapshot(BaseModel):
    model_config = ConfigDict(extra="forbid")
    ts: float = Field(default_factory=lambda: time.time())
    code: str = ""
    user_message: str = ""


class StateMachineSnapshot(BaseModel):
    model_config = ConfigDict(extra="forbid")
    last_state: str = "SLEEPING"
    last_trace_id: Optional[str] = None
    last_transition_at: float = Field(default_factory=lambda: time.time())


class LlmRoleSnapshot(BaseModel):
    model_config = ConfigDict(extra="forbid")
    loaded: Optional[bool] = None
    idle_seconds: Optional[float] = None
    last_error: Optional[str] = None
    disabled: Optional[bool] = None


class LlmSnapshot(BaseModel):
    model_config = ConfigDict(extra="forbid")
    roles: Dict[str, LlmRoleSnapshot] = Field(default_factory=dict)
    breaker: BreakerSnapshot = Field(default_factory=BreakerSnapshot)
    consecutive_failures: int = 0


class WebSnapshot(BaseModel):
    model_config = ConfigDict(extra="forbid")
    enabled: bool = False
    bind_host: Optional[str] = None
    port: Optional[int] = None
    allow_remote: Optional[bool] = None
    thread_alive: Optional[bool] = None


class JobsSnapshot(BaseModel):
    model_config = ConfigDict(extra="forbid")
    last_job_id: Optional[str] = None
    last_job_error: Optional[str] = None
    queued: Optional[int] = None
    running: Optional[int] = None


class TelemetrySummary(BaseModel):
    model_config = ConfigDict(extra="forbid")
    ts: float = Field(default_factory=lambda: time.time())
    health_counts: Dict[str, int] = Field(default_factory=dict)  # OK/DEGRADED/DOWN/UNKNOWN
    cpu_system_percent: Optional[float] = None
    ram_system_percent: Optional[float] = None
    disk_logs_percent_used: Optional[float] = None


class ConfigFingerprints(BaseModel):
    model_config = ConfigDict(extra="forbid")
    last_validated_at: float = Field(default_factory=lambda: time.time())
    last_migrated_config_version: Optional[int] = None
    files: Dict[str, str] = Field(default_factory=dict)  # filename -> sha256 hex


class CrashMarkers(BaseModel):
    model_config = ConfigDict(extra="forbid")
    dirty_shutdown_detected: bool = False
    last_shutdown_reason: Optional[str] = None
    last_shutdown_completed_at: Optional[float] = None
    last_startup_at: float = Field(default_factory=lambda: time.time())
    recovered_from_crash_at: Optional[float] = None
    restart_marker: Optional[Dict[str, Any]] = None


class SecurityState(BaseModel):
    model_config = ConfigDict(extra="forbid")
    admin_locked: bool = True  # hard rule: always true on disk
    last_admin_unlock_at: Optional[float] = None
    failed_admin_attempts: int = 0
    lockouts_summary: Dict[str, Any] = Field(default_factory=dict)  # counts only; no keys


class RuntimeState(BaseModel):
    model_config = ConfigDict(extra="forbid")

    state_version: int = Field(default=1, ge=1)
    created_at: float = Field(default_factory=lambda: time.time())
    updated_at: float = Field(default_factory=lambda: time.time())

    security: SecurityState = Field(default_factory=SecurityState)
    state_machine: StateMachineSnapshot = Field(default_factory=StateMachineSnapshot)
    llm: LlmSnapshot = Field(default_factory=LlmSnapshot)
    voice: Dict[str, Any] = Field(default_factory=dict)  # informational flags only
    web: WebSnapshot = Field(default_factory=WebSnapshot)
    jobs: JobsSnapshot = Field(default_factory=JobsSnapshot)
    telemetry: Optional[TelemetrySummary] = None
    errors_by_subsystem: Dict[str, LastErrorSnapshot] = Field(default_factory=dict)
    breakers: Dict[str, BreakerSnapshot] = Field(default_factory=dict)
    config: ConfigFingerprints = Field(default_factory=ConfigFingerprints)
    crash: CrashMarkers = Field(default_factory=CrashMarkers)

    notes: List[str] = Field(default_factory=list)

