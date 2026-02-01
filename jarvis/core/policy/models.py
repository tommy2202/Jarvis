from __future__ import annotations

import time
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field


class PolicyEffect(str, Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    MODIFY = "MODIFY"
    REQUIRE_ADMIN = "REQUIRE_ADMIN"
    REQUIRE_CONFIRMATION = "REQUIRE_CONFIRMATION"


class PolicySeverity(str, Enum):
    INFO = "INFO"
    WARN = "WARN"
    ERROR = "ERROR"


class TimeWindow(BaseModel):
    model_config = ConfigDict(extra="forbid")

    start: str  # HH:MM
    end: str  # HH:MM
    timezone: str = "UTC"


class PolicyMatch(BaseModel):
    model_config = ConfigDict(extra="forbid")

    intent_id_in: Optional[List[str]] = None
    intent_id_not_in: Optional[List[str]] = None

    capabilities_all: Optional[List[str]] = None
    capabilities_any: Optional[List[str]] = None
    capabilities_not: Optional[List[str]] = None

    source_in: Optional[List[str]] = None
    source_not_in: Optional[List[str]] = None

    is_admin: Optional[bool] = None
    safe_mode: Optional[bool] = None
    shutting_down: Optional[bool] = None

    secure_store_status_in: Optional[List[str]] = None
    resource_over_budget: Optional[bool] = None

    time_window: Optional[TimeWindow] = None
    day_of_week_in: Optional[List[str]] = None  # Mon..Sun

    tags_any: Optional[List[str]] = None
    tags_all: Optional[List[str]] = None

    client_ip_in: Optional[List[str]] = None
    client_ip_not_in: Optional[List[str]] = None

    rate_limited: Optional[bool] = None


class PolicyModify(BaseModel):
    model_config = ConfigDict(extra="forbid")

    flags: Dict[str, Any] = Field(default_factory=dict)  # tts_enabled, voice_enabled, allow_network, allow_subprocess
    llm_params: Dict[str, Any] = Field(default_factory=dict)  # max_tokens cap, temperature cap, role override (chat only)
    execution: Dict[str, Any] = Field(default_factory=dict)  # max_runtime_seconds cap, force_profile=low


class PolicyRule(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str = Field(min_length=1, max_length=128)
    description: str = ""
    priority: int = Field(default=50, ge=0, le=1000)
    effect: PolicyEffect
    match: PolicyMatch = Field(default_factory=PolicyMatch)
    reason: str = Field(default="", max_length=300)
    remediation: str = Field(default="", max_length=300)
    modify: Optional[PolicyModify] = None


class PolicyDefaults(BaseModel):
    model_config = ConfigDict(extra="forbid")

    deny_unknown_intents: bool = True
    deny_high_sensitivity_without_admin: bool = True


class PolicyConfigFile(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: int = Field(default=1, ge=1, le=10)
    enabled: bool = True
    default: PolicyDefaults = Field(default_factory=PolicyDefaults)
    rules: List[PolicyRule] = Field(default_factory=list)


class MatchedRule(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    effect: PolicyEffect
    reason: str
    priority: int


class PolicyDecision(BaseModel):
    model_config = ConfigDict(extra="forbid")

    allowed: bool
    required_admin: bool = False
    require_confirmation: bool = False
    modifications: Dict[str, Any] = Field(default_factory=dict)
    matched_rules: List[MatchedRule] = Field(default_factory=list)
    final_reason: str = ""
    remediation: str = ""
    severity: PolicySeverity = PolicySeverity.INFO
    decided_at: float = Field(default_factory=lambda: time.time())
    failsafe: bool = False


class PolicyContext(BaseModel):
    """
    Policy evaluation input (derived from capability/dispatcher contexts).
    Keep it privacy-safe: no raw user text.
    """

    model_config = ConfigDict(extra="forbid")

    trace_id: str
    intent_id: str
    required_capabilities: List[str] = Field(default_factory=list)
    source: str = "cli"
    client_id: Optional[str] = None
    client_ip: Optional[str] = None

    is_admin: bool = False
    safe_mode: bool = False
    shutting_down: bool = False
    secure_store_mode: Optional[str] = None

    tags: List[str] = Field(default_factory=list)
    resource_over_budget: Optional[bool] = None
    rate_limited: Optional[bool] = None
    confirmed: bool = False

