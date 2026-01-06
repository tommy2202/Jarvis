from __future__ import annotations

from typing import Any, Dict, Optional

from pydantic import BaseModel, Field


class ClientInfo(BaseModel):
    name: Optional[str] = None
    id: Optional[str] = None


class MessageRequest(BaseModel):
    message: str = Field(min_length=1, max_length=4000)
    client: Optional[ClientInfo] = None


class IntentInfo(BaseModel):
    id: str
    source: str
    confidence: float


class MessageResponse(BaseModel):
    trace_id: str
    reply: str
    intent: IntentInfo
    requires_followup: bool
    followup_question: Optional[str] = None


class AdminUnlockRequest(BaseModel):
    passphrase: str = Field(min_length=1, max_length=512)


class AdminUnlockResponse(BaseModel):
    ok: bool
    message: str


class JobSubmitRequest(BaseModel):
    kind: str = Field(min_length=1, max_length=128)
    args: Dict[str, Any] = Field(default_factory=dict)
    priority: int = Field(default=50, ge=0, le=1000)
    max_runtime_seconds: Optional[int] = Field(default=None, ge=1, le=86400)


class JobSubmitResponse(BaseModel):
    job_id: str


class JobStateResponse(BaseModel):
    job: Dict[str, Any]


class JobListResponse(BaseModel):
    jobs: list[Dict[str, Any]]

