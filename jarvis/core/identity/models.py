from __future__ import annotations

import time
import uuid
from enum import Enum
from typing import Optional

from pydantic import BaseModel, ConfigDict, Field


def _iso_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


class UserRole(str, Enum):
    user = "user"
    admin = "admin"


class UserIdentity(BaseModel):
    model_config = ConfigDict(extra="forbid")

    user_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    display_name: str = Field(default="", max_length=120)
    role: UserRole = UserRole.user
    created_at: str = Field(default_factory=_iso_now)
    last_active_at: str = Field(default_factory=_iso_now)


class ActiveSession(BaseModel):
    model_config = ConfigDict(extra="forbid")

    session_id: str = Field(default_factory=lambda: uuid.uuid4().hex)
    user_id: str
    is_admin: bool = False
    started_at: str = Field(default_factory=_iso_now)
    expires_at: Optional[str] = None

