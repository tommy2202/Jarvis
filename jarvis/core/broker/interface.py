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
    ok: Optional[bool] = None
    denied_by: Optional[str] = None
    remediation: Optional[str] = None
    result: Optional[Dict[str, Any]] = None
    artifacts: Optional[list[dict]] = None

    def model_post_init(self, __context: Any) -> None:  # noqa: ANN001
        if self.ok is None:
            self.ok = bool(self.allowed)
        if self.result is None and self.output is not None:
            self.result = self.output


class ToolBroker(ABC):
    @abstractmethod
    def run(self, tool_name: str, args: Dict[str, Any], context: Dict[str, Any]) -> ToolResult:
        raise NotImplementedError
