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
    job_thread = "job_thread"
    job_process = "job_process"


class ModuleIntentContract(BaseModel):
    model_config = ConfigDict(extra="forbid")

    intent_id: str = Field(min_length=1)
    description: str = ""
    args_schema: Dict[str, Any] = Field(default_factory=dict)
    required_capabilities: List[str] = Field(default_factory=list)
    resource_class: ResourceClass = ResourceClass.light
    execution_mode: ExecutionMode = ExecutionMode.inline

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
    contract_hash: str = ""
    module_path: str = ""

    safe_auto_enabled: bool = False
    requires_admin_to_enable: bool = False
    reason: str = ""

    missing_on_disk: bool = False
    pending_user_input: bool = False
    changed_requires_review: bool = False


class ModulesRegistryFile(BaseModel):
    """
    Stored in config/modules.json alongside existing `intents` list.
    """

    model_config = ConfigDict(extra="forbid")

    schema_version: int = Field(default=1, ge=1, le=10)
    intents: List[Dict[str, Any]] = Field(default_factory=list)
    modules: Dict[str, InstalledModuleRecord] = Field(default_factory=dict)

