from __future__ import annotations

"""
Module contract models (manifest + installed registry).

WHY THIS FILE EXISTS:
We must treat the module manifest as the contract-of-record and enforce install/
enable gating deterministically. These models are used for validation without
importing module code.
"""

import re
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator


class ResourceClass(str, Enum):
    light = "light"
    medium = "medium"
    heavy = "heavy"


class ExecutionMode(str, Enum):
    inline = "inline"
    thread = "thread"
    process = "process"


class ModuleIntentContract(BaseModel):
    model_config = ConfigDict(extra="forbid")

    intent_id: str = Field(min_length=1)
    description: str = ""
    args_schema: Dict[str, Any] = Field(default_factory=dict)
    required_capabilities: List[str] = Field(default_factory=list)
    resource_class: ResourceClass = ResourceClass.light
    execution_mode: ExecutionMode = ExecutionMode.process

    @field_validator("execution_mode", mode="before")
    @classmethod
    def _norm_execution_mode(cls, v: Any) -> Any:
        if v is None or v == "":
            return ExecutionMode.process
        if isinstance(v, ExecutionMode):
            return v
        vv = str(v or "").strip().lower()
        if vv in {"process", "job_process"}:
            return ExecutionMode.process
        if vv in {"thread", "job_thread"}:
            return ExecutionMode.thread
        if vv == "inline":
            return ExecutionMode.inline
        return v

    @field_validator("required_capabilities", mode="before")
    @classmethod
    def _norm_caps(cls, v: Any) -> List[str]:
        if v is None:
            return []
        if isinstance(v, str):
            return [v]
        if isinstance(v, list):
            return [str(x) for x in v if str(x or "").strip()]
        return []


class ModuleDefaults(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled_by_default: bool = False
    admin_required_to_enable: bool = False


class ModuleManifest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: int = Field(default=1, ge=1, le=10)
    module_id: str = Field(min_length=1)
    version: str = Field(default="0.1.0", min_length=1)
    display_name: str = Field(default="", max_length=80)
    description: str = Field(default="", max_length=300)
    entrypoint: str = Field(min_length=1)  # string only; never imported during discovery
    intents: List[ModuleIntentContract] = Field(default_factory=list)
    module_defaults: ModuleDefaults = Field(default_factory=ModuleDefaults)

    @field_validator("module_id")
    @classmethod
    def _module_id_safe(cls, v: str) -> str:
        v = str(v or "").strip()
        if not v:
            raise ValueError("module_id required")
        # allow dots for ids (notes.local), but keep it conservative
        if not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}", v):
            raise ValueError("module_id contains invalid characters")
        return v


class InstalledModuleRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")

    installed: bool = True
    enabled: bool = False
    installed_at: str = ""
    enabled_at: Optional[str] = None

    last_seen_fingerprint: str = ""
    # Explicit fingerprint field for provenance/trust decisions (alias of last_seen_fingerprint).
    fingerprint_hash: str = ""
    contract_hash: str = ""
    module_path: str = ""

    provenance: str = "local"  # local|git|manual
    trusted: bool = True

    safe_auto_enabled: bool = False
    requires_admin_to_enable: bool = False
    reason: str = ""

    missing_on_disk: bool = False
    pending_user_input: bool = False
    changed_requires_review: bool = False
    # Debounce: fingerprint that triggered changed_requires_review.
    changed_requires_review_fingerprint: str = ""


class ModulesRegistryFile(BaseModel):
    """
    Stored in config/modules.json alongside existing `intents` list.
    """

    model_config = ConfigDict(extra="forbid")

    schema_version: int = Field(default=1, ge=1, le=10)
    intents: List[Dict[str, Any]] = Field(default_factory=list)
    modules: Dict[str, InstalledModuleRecord] = Field(default_factory=dict)


class ModuleState(str, Enum):
    DISCOVERED = "DISCOVERED"
    PENDING_INSTALL = "PENDING_INSTALL"
    INSTALLED_DISABLED = "INSTALLED_DISABLED"
    INSTALLED_ENABLED = "INSTALLED_ENABLED"
    BLOCKED = "BLOCKED"
    MISSING_ON_DISK = "MISSING_ON_DISK"
    CHANGED_REVIEW_REQUIRED = "CHANGED_REVIEW_REQUIRED"
    ERROR = "ERROR"


class ModuleReasonCode(str, Enum):
    NO_MANIFEST = "NO_MANIFEST"
    MANIFEST_INVALID = "MANIFEST_INVALID"
    CAPABILITIES_MAPPING_MISSING = "CAPABILITIES_MAPPING_MISSING"
    REQUIRES_ADMIN_TO_ENABLE = "REQUIRES_ADMIN_TO_ENABLE"
    CHANGED_CONTRACT_REVIEW_REQUIRED = "CHANGED_CONTRACT_REVIEW_REQUIRED"
    DISABLED_BY_POLICY = "DISABLED_BY_POLICY"
    MISSING_ON_DISK = "MISSING_ON_DISK"
    UNKNOWN = "UNKNOWN"


class ModuleStatus(BaseModel):
    """
    Canonical module status model. Safe to display in CLI/UI/web and to include in audit logs.
    """

    model_config = ConfigDict(extra="forbid")

    module_id: str = Field(min_length=1)
    state: ModuleState
    reason_code: ModuleReasonCode = ModuleReasonCode.UNKNOWN
    reason_human: str = Field(default="", max_length=200)
    remediation: str = Field(default="", max_length=200)
    last_seen_at: str = Field(default="", min_length=1)
    fingerprint_short: str = Field(default="", max_length=8)
    safe_auto_enabled: bool = False
    requires_admin_to_enable: bool = False


class ModuleTrustConfigFile(BaseModel):
    """
    config/module_trust.json schema.
    """

    model_config = ConfigDict(extra="forbid")

    allow_unsigned_modules: bool = False
    trusted_module_ids: List[str] = Field(default_factory=list)
    dev_mode_override: bool = False
    dev_mode: bool = False
    scan_mode: str = "startup_only"

    @field_validator("trusted_module_ids", mode="before")
    @classmethod
    def _normalize_trusted_module_ids(cls, v: Any) -> List[str]:
        if v is None:
            return []
        if isinstance(v, str):
            v = [v]
        if isinstance(v, list):
            out: List[str] = []
            for item in v:
                s = str(item or "").strip()
                if not s:
                    continue
                out.append(s)
            return sorted(set(out))
        return []


def default_module_trust_config_dict() -> Dict[str, Any]:
    return ModuleTrustConfigFile().model_dump()

