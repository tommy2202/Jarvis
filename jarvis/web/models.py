from __future__ import annotations

from typing import Any, Dict, Optional

from pydantic import BaseModel, Field, ConfigDict


class ClientInfo(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: Optional[str] = None
    id: Optional[str] = None


class MessageRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    message: str = Field(min_length=1, max_length=2000)
    client: Optional[ClientInfo] = None


class IntentInfo(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str
    source: str
    confidence: float


class MessageResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    trace_id: str
    reply: str
    intent: IntentInfo
    requires_followup: bool
    followup_question: Optional[str] = None


class AdminUnlockRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    passphrase: str = Field(min_length=1, max_length=256)


class AdminUnlockResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    ok: bool
    message: str


class JobSubmitRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    kind: str = Field(min_length=1, max_length=128)
    args: Dict[str, Any] = Field(default_factory=dict)
    priority: int = Field(default=50, ge=0, le=1000)
    max_runtime_seconds: Optional[int] = Field(default=None, ge=1, le=86400)


class JobSubmitResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    job_id: str


class JobStateResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    job: Dict[str, Any]


class JobListResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")
    jobs: list[Dict[str, Any]]

