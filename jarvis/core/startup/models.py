from __future__ import annotations

import time
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field


class CheckStatus(str, Enum):
    OK = "OK"
    DEGRADED = "DEGRADED"
    FAILED = "FAILED"


class OverallStatus(str, Enum):
    OK = "OK"
    DEGRADED = "DEGRADED"
    BLOCKED = "BLOCKED"


class Severity(str, Enum):
    INFO = "INFO"
    WARN = "WARN"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


class CheckResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    check_id: str
    status: CheckStatus
    message: str
    remediation: Optional[str] = None
    severity: Severity = Severity.INFO


class PhaseResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    phase_id: int
    name: str
    status: CheckStatus
    checks: List[CheckResult] = Field(default_factory=list)


class StartupCheckResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    overall_status: OverallStatus
    started_in_safe_mode: bool
    phases: List[PhaseResult]
    blocking_reasons: List[str] = Field(default_factory=list)
    warnings: List[str] = Field(default_factory=list)
    remediation_steps: List[str] = Field(default_factory=list)
    timestamp: float = Field(default_factory=lambda: time.time())
    runtime_fingerprint: str = ""

