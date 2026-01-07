from __future__ import annotations

import time
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field


class Subsystem(str, Enum):
    config = "config"
    secure_store = "secure_store"
    state_machine = "state_machine"
    dispatcher = "dispatcher"
    intent_router = "intent_router"
    llm = "llm"
    jobs = "jobs"
    web = "web"
    voice = "voice"
    stt = "stt"
    tts = "tts"
    ui = "ui"


class HealthStatus(str, Enum):
    OK = "OK"
    DEGRADED = "DEGRADED"
    DOWN = "DOWN"
    UNKNOWN = "UNKNOWN"


class HealthCheckResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    subsystem: Subsystem
    status: HealthStatus
    message: str
    last_checked_at: float = Field(default_factory=lambda: time.time())
    last_ok_at: Optional[float] = None
    details: Dict[str, Any] = Field(default_factory=dict)
    latency_ms: Optional[float] = None
    error_code: Optional[str] = None
    consecutive_failures: int = 0
    circuit_breaker_state: Optional[str] = None
    remediation: str = ""


class ResourceSample(BaseModel):
    model_config = ConfigDict(extra="forbid")

    sampled_at: float = Field(default_factory=lambda: time.time())
    cpu_system_percent: Optional[float] = None
    cpu_process_percent: Optional[float] = None
    ram_system_percent: Optional[float] = None
    ram_process_rss_bytes: Optional[int] = None
    disk_root_percent_used: Optional[float] = None
    disk_logs_percent_used: Optional[float] = None
    gpu: Dict[str, Any] = Field(default_factory=dict)  # best-effort; safe small dict


class HealthEvent(BaseModel):
    model_config = ConfigDict(extra="forbid")

    ts: float = Field(default_factory=lambda: time.time())
    trace_id: str
    event_type: str  # health_change|resource_alert
    subsystem: Optional[Subsystem] = None
    old_status: Optional[HealthStatus] = None
    new_status: Optional[HealthStatus] = None
    message: str = ""
    details: Dict[str, Any] = Field(default_factory=dict)


class MetricSummary(BaseModel):
    model_config = ConfigDict(extra="forbid")

    counters: Dict[str, int] = Field(default_factory=dict)
    gauges: Dict[str, Any] = Field(default_factory=dict)
    histograms: Dict[str, Dict[str, float]] = Field(default_factory=dict)  # {metric: {p50,p95,avg,max,min,count}}


class TelemetrySnapshot(BaseModel):
    model_config = ConfigDict(extra="forbid")

    ts: float = Field(default_factory=lambda: time.time())
    uptime_seconds: float
    health: List[HealthCheckResult]
    metrics: MetricSummary
    resources: ResourceSample
    recent_events: List[HealthEvent] = Field(default_factory=list)

