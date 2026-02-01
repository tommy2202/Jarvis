from __future__ import annotations

from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field


class ExecutionBackend(str, Enum):
    inline = "inline"
    local_thread = "local_thread"
    local_process = "local_process"
    sandbox = "sandbox"


class ToolCall(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tool_name: str
    tool_args: Dict[str, Any] = Field(default_factory=dict)
    requested_caps: List[str] = Field(default_factory=list)
    expected_artifacts: List[str] = Field(default_factory=list)


class ExecutionPlan(BaseModel):
    model_config = ConfigDict(extra="forbid")

    backend: ExecutionBackend
    mode: str = ""
    reason: str = ""
    fallback_used: bool = False
    tool_calls: List[ToolCall] = Field(default_factory=list)


class ExecutionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", arbitrary_types_allowed=True)

    trace_id: str
    intent_id: str
    module_id: str
    args: Dict[str, Any] = Field(default_factory=dict)
    context: Dict[str, Any] = Field(default_factory=dict)
    required_capabilities: List[str] = Field(default_factory=list)
    execution_mode: str = "process"
    is_core: bool = False
    allow_inline_intents: List[str] = Field(default_factory=list)
    default_backend: ExecutionBackend = ExecutionBackend.sandbox
    fallback_backend: ExecutionBackend = ExecutionBackend.local_process
    sandbox_require_available: bool = True
    sandbox_available: bool = True
    module_path: str = ""
    loaded_module: Any = None
    persist_allowed: bool = True
    tool_broker: Any = None
    execution_plan: Optional[ExecutionPlan] = None


class ExecutionResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    ok: bool
    backend: ExecutionBackend
    exec_mode: str = ""
    trace_id: str = ""
    output: Optional[Dict[str, Any]] = None
    error: str = ""
    warning: Optional[Dict[str, Any]] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)
