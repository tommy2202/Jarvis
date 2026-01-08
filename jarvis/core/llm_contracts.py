from __future__ import annotations

import json
import time
from enum import Enum
from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, Field


class LLMRole(str, Enum):
    chat = "chat"
    coder = "coder"


class OutputSchema(str, Enum):
    chat_reply = "chat_reply"
    intent_fallback = "intent_fallback"


class Message(BaseModel):
    role: Literal["system", "user", "assistant"]
    content: str = Field(min_length=0, max_length=20000)


class SafetySpec(BaseModel):
    allowed_intents: List[str] = Field(default_factory=list)
    denylist_phrases: List[str] = Field(default_factory=list)


class LLMRequest(BaseModel):
    trace_id: str
    role: LLMRole
    messages: List[Message]
    output_schema: OutputSchema
    safety: SafetySpec = Field(default_factory=SafetySpec)
    max_tokens: int = Field(default=512, ge=1, le=4096)
    temperature: float = Field(default=0.7, ge=0.0, le=2.0)


class ChatReply(BaseModel):
    reply: str


class IntentFallback(BaseModel):
    intent_id: str
    confidence: float = Field(ge=0.0, le=1.0)
    args: Dict[str, Any] = Field(default_factory=dict)
    confirmation_text: str
    requires_admin: bool = False


class LLMError(BaseModel):
    type: str
    message: str


class LLMStatus(str, Enum):
    ok = "ok"
    invalid = "invalid"
    timeout = "timeout"
    error = "error"


class LLMResponse(BaseModel):
    trace_id: str
    role: LLMRole
    status: LLMStatus
    raw_text: Optional[str] = None
    parsed_json: Optional[Dict[str, Any]] = None
    error: Optional[LLMError] = None
    latency_seconds: float = 0.0


def parse_strict_json(raw_text: str) -> Dict[str, Any]:
    """
    Strict JSON parser with minimal tolerance for leading/trailing whitespace.
    """
    s = (raw_text or "").strip()
    if not s:
        raise ValueError("empty response")
    obj = json.loads(s)
    if not isinstance(obj, dict):
        raise ValueError("LLM output must be a JSON object.")
    return obj


def validate_schema(output_schema: OutputSchema, obj: Dict[str, Any]) -> Dict[str, Any]:
    if output_schema == OutputSchema.chat_reply:
        return ChatReply.model_validate(obj).model_dump()
    if output_schema == OutputSchema.intent_fallback:
        return IntentFallback.model_validate(obj).model_dump()
    raise ValueError("Unknown output_schema")

