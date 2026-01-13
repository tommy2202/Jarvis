from __future__ import annotations

import time
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field


class CapabilitySensitivity(str, Enum):
    normal = "normal"
    high = "high"


class DefaultPolicy(str, Enum):
    allow = "allow"
    deny = "deny"


class CapabilityDefinition(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    description: str
    default_policy: DefaultPolicy = DefaultPolicy.deny
    sensitivity: CapabilitySensitivity = CapabilitySensitivity.normal
    requires_admin: bool = False
    requires_secrets: bool = False
    audit: bool = False


class SourcePolicy(BaseModel):
    model_config = ConfigDict(extra="forbid")

    deny: List[str] = Field(default_factory=list)  # capability ids
    require_admin_for: List[str] = Field(default_factory=list)  # capability ids
    allow_all_non_sensitive: bool = False


class SafeModePolicy(BaseModel):
    model_config = ConfigDict(extra="forbid")
    deny: List[str] = Field(default_factory=list)  # capability ids


class CapabilitiesConfig(BaseModel):
    """
    config/capabilities.json schema.
    """

    model_config = ConfigDict(extra="forbid")

    capabilities: Dict[str, CapabilityDefinition]
    intent_requirements: Dict[str, List[str]] = Field(default_factory=dict)
    source_policies: Dict[str, SourcePolicy] = Field(default_factory=dict)
    safe_mode: SafeModePolicy = Field(default_factory=SafeModePolicy)
    heavy_compute_whitelist_intents: List[str] = Field(default_factory=list)


class RequestSource(str, Enum):
    voice = "voice"
    cli = "cli"
    web = "web"
    ui = "ui"
    system = "system"


class RequestContext(BaseModel):
    model_config = ConfigDict(extra="forbid")

    trace_id: str
    source: RequestSource
    client_id: Optional[str] = None
    # Privacy core: single-user mode default. Call sites do not need updating.
    user_id: str = "default"
    is_admin: bool = False
    safe_mode: bool = False
    shutting_down: bool = False
    subsystem_health: Dict[str, Any] = Field(default_factory=dict)  # e.g. breaker states
    intent_id: str
    resource_intensive: bool = False
    network_requested: bool = False
    secure_store_mode: Optional[str] = None  # READY|KEY_MISSING|...
    confirmed: bool = False


class DecisionSeverity(str, Enum):
    INFO = "INFO"
    WARN = "WARN"
    ERROR = "ERROR"


class CapabilityDecision(BaseModel):
    model_config = ConfigDict(extra="forbid")

    allowed: bool
    require_confirmation: bool = False
    modifications: Dict[str, Any] = Field(default_factory=dict)
    denied_capabilities: List[str] = Field(default_factory=list)
    required_capabilities: List[str] = Field(default_factory=list)
    reasons: List[str] = Field(default_factory=list)
    remediation: str = ""
    severity: DecisionSeverity = DecisionSeverity.INFO
    audit_event: Dict[str, Any] = Field(default_factory=dict)
    decided_at: float = Field(default_factory=lambda: time.time())

