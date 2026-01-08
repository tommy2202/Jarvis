from __future__ import annotations

import time
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field


class AdmissionAction(str, Enum):
    ALLOW = "ALLOW"
    DELAY = "DELAY"
    DENY = "DENY"
    THROTTLE = "THROTTLE"


class OverBudgetPolicy(str, Enum):
    THROTTLE = "THROTTLE"
    DELAY = "DELAY"
    DENY = "DENY"
    SAFE_MODE = "SAFE_MODE"


class ResourceSnapshot(BaseModel):
    model_config = ConfigDict(extra="forbid")

    sampled_at: float = Field(default_factory=lambda: time.time())

    cpu_system_percent: Optional[float] = None
    cpu_process_percent: Optional[float] = None
    ram_system_percent: Optional[float] = None
    ram_process_rss_bytes: Optional[int] = None

    disk_root_free_bytes: Optional[int] = None
    disk_logs_free_bytes: Optional[int] = None

    gpu_status: str = "unknown"  # ok|unavailable|disabled|error|unknown
    gpu_vram_max_percent: Optional[float] = None  # max percent across GPUs

    def public_dict(self) -> Dict[str, Any]:
        return {
            "sampled_at": self.sampled_at,
            "cpu_system_percent": self.cpu_system_percent,
            "cpu_process_percent": self.cpu_process_percent,
            "ram_system_percent": self.ram_system_percent,
            "ram_process_rss_mb": (float(self.ram_process_rss_bytes) / (1024 * 1024)) if self.ram_process_rss_bytes is not None else None,
            "disk_root_free_gb": (float(self.disk_root_free_bytes) / (1024 * 1024 * 1024)) if self.disk_root_free_bytes is not None else None,
            "disk_logs_free_gb": (float(self.disk_logs_free_bytes) / (1024 * 1024 * 1024)) if self.disk_logs_free_bytes is not None else None,
            "gpu": {"status": self.gpu_status, "vram_max_percent": self.gpu_vram_max_percent},
        }


class BudgetConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    cpu_max_percent: float = Field(default=85.0, ge=1.0, le=100.0)
    ram_max_percent: float = Field(default=85.0, ge=1.0, le=100.0)
    process_ram_max_mb: int = Field(default=8000, ge=128, le=262144)
    disk_min_free_gb: float = Field(default=5.0, ge=0.1, le=1024.0)
    gpu_vram_max_percent: float = Field(default=90.0, ge=1.0, le=100.0)


class PolicyConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    on_over_budget: OverBudgetPolicy = OverBudgetPolicy.THROTTLE
    cooldown_seconds: float = Field(default=30.0, ge=0.0, le=3600.0)
    max_delay_seconds: float = Field(default=15.0, ge=0.0, le=120.0)


class ThrottleConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    max_concurrent_heavy_jobs: int = Field(default=1, ge=0, le=32)
    max_concurrent_llm_requests: int = Field(default=1, ge=0, le=32)
    max_total_jobs: int = Field(default=2, ge=0, le=64)


class SafeModeConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enter_after_consecutive_violations: int = Field(default=5, ge=1, le=100)
    exit_after_seconds_stable: float = Field(default=120.0, ge=1.0, le=86400.0)
    deny_caps: List[str] = Field(default_factory=lambda: ["CAP_NETWORK_ACCESS", "CAP_RUN_SUBPROCESS", "CAP_HEAVY_COMPUTE"])


class GatingConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    heavy_compute_capability: str = "CAP_HEAVY_COMPUTE"
    subprocess_capability: str = "CAP_RUN_SUBPROCESS"
    network_capability: str = "CAP_NETWORK_ACCESS"
    llm_capability: str = "CAP_HEAVY_COMPUTE"


class ResourceGovernorConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool = True
    sample_interval_seconds: float = Field(default=2.0, ge=0.2, le=60.0)
    budgets: BudgetConfig = Field(default_factory=BudgetConfig)
    policies: PolicyConfig = Field(default_factory=PolicyConfig)
    gating: GatingConfig = Field(default_factory=GatingConfig)
    throttles: ThrottleConfig = Field(default_factory=ThrottleConfig)
    safe_mode: SafeModeConfig = Field(default_factory=SafeModeConfig)


class AdmissionDecision(BaseModel):
    model_config = ConfigDict(extra="forbid")

    allowed: bool
    action: AdmissionAction
    delay_seconds: float = 0.0
    reasons: List[str] = Field(default_factory=list)
    remediation: str = ""
    snapshot: Dict[str, Any] = Field(default_factory=dict)

