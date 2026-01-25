from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Dict, Optional

from pydantic import BaseModel, ConfigDict, Field


class ToolCall(BaseModel):
    model_config = ConfigDict(extra="forbid")

    tool_name: str
    args: Dict[str, Any] = Field(default_factory=dict)
    context: Dict[str, Any] = Field(default_factory=dict)
    trace_id: str = "tool"


class ToolResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    allowed: bool
    reason_code: str
    trace_id: str
    output: Optional[Dict[str, Any]] = None
    error: Optional[str] = None


class ToolBroker(ABC):
    @abstractmethod
    def run(self, tool_name: str, args: Dict[str, Any], context: Dict[str, Any]) -> ToolResult:
        raise NotImplementedError
