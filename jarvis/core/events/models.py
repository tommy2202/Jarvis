from __future__ import annotations

import json
import time
import uuid
from enum import Enum
from typing import Any, Dict, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator

from jarvis.core.events.legacy import redact


class EventSeverity(str, Enum):
    INFO = "INFO"
    WARN = "WARN"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


class SourceSubsystem(str, Enum):
    state_machine = "state_machine"
    dispatcher = "dispatcher"
    llm = "llm"
    image = "image"
    jobs = "jobs"
    web = "web"
    voice = "voice"
    ui = "ui"
    telemetry = "telemetry"
    recovery = "recovery"
    audit = "audit"
    modules = "modules"


class BaseEvent(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    event_id: str = Field(default_factory=lambda: uuid.uuid4().hex)
    event_type: str
    timestamp: float = Field(default_factory=lambda: time.time())
    trace_id: Optional[str] = None
    source_subsystem: SourceSubsystem
    severity: EventSeverity = EventSeverity.INFO
    payload: Dict[str, Any] = Field(default_factory=dict)

    @field_validator("event_type")
    @classmethod
    def _non_empty(cls, v: str) -> str:
        v = str(v or "").strip()
        if not v:
            raise ValueError("event_type required")
        return v

    @field_validator("payload")
    @classmethod
    def _jsonable_and_redacted(cls, v: Dict[str, Any]) -> Dict[str, Any]:
        if not isinstance(v, dict):
            raise ValueError("payload must be an object")
        safe = redact(v)
        try:
            json.dumps(safe, ensure_ascii=False)
        except Exception as e:  # noqa: BLE001
            raise ValueError("payload must be JSON-serializable") from e
        return safe

