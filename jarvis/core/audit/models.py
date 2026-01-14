from __future__ import annotations

import time
import uuid
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field


class AuditSeverity(str, Enum):
    INFO = "INFO"
    WARN = "WARN"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"


class AuditOutcome(str, Enum):
    success = "success"
    denied = "denied"
    failed = "failed"
    timeout = "timeout"
    canceled = "canceled"


class ActorSource(str, Enum):
    voice = "voice"
    cli = "cli"
    web = "web"
    ui = "ui"
    system = "system"


class ActorUser(str, Enum):
    admin = "admin"
    user = "user"
    unknown = "unknown"


class AuditCategory(str, Enum):
    lifecycle = "lifecycle"
    security = "security"
    permission = "permission"
    execution = "execution"
    job = "job"
    llm = "llm"
    voice = "voice"
    web = "web"
    config = "config"
    error = "error"
    recovery = "recovery"


class Actor(BaseModel):
    model_config = ConfigDict(extra="forbid")

    source: ActorSource = ActorSource.system
    client_id: Optional[str] = None
    user: ActorUser = ActorUser.unknown
    user_id: Optional[str] = None


class AuditEvent(BaseModel):
    model_config = ConfigDict(extra="forbid")

    audit_id: str = Field(default_factory=lambda: uuid.uuid4().hex)
    timestamp: float = Field(default_factory=lambda: time.time())
    trace_id: Optional[str] = None

    actor: Actor = Field(default_factory=Actor)
    category: AuditCategory
    action: str
    outcome: AuditOutcome
    summary: str
    details: Dict[str, Any] = Field(default_factory=dict)
    severity: AuditSeverity = AuditSeverity.INFO


class IntegrityReport(BaseModel):
    model_config = ConfigDict(extra="forbid")

    ok: bool
    checked: int
    broken_at_line: Optional[int] = None
    message: str = ""
    head_hash: Optional[str] = None

