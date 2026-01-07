from __future__ import annotations

import time
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field


class ManifestFileEntry(BaseModel):
    model_config = ConfigDict(extra="forbid")

    relative_path: str
    size_bytes: int
    sha256: str


class SecureStoreInfo(BaseModel):
    model_config = ConfigDict(extra="forbid")

    included: bool = True
    store_meta_fingerprint: Dict[str, Any] = Field(default_factory=dict)  # key_id/store_id/store_version


class BackupManifest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    backup_id: str
    created_at: float = Field(default_factory=lambda: time.time())
    profile: str

    jarvis_version: str = "unknown"
    git_commit: Optional[str] = None
    python_version: str = ""
    os_info: str = ""

    config_version: Optional[int] = None
    runtime_state_version: Optional[int] = None

    contents: List[ManifestFileEntry] = Field(default_factory=list)
    secure_store: SecureStoreInfo = Field(default_factory=SecureStoreInfo)
    warnings: List[str] = Field(default_factory=list)
    redaction_applied: bool = False

