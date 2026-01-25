from __future__ import annotations

import time
import uuid
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator


def _iso_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


class DataCategory(str, Enum):
    """
    High-level data inventory categories.
    Keep these stable: they become keys in privacy.json retention config.
    """

    AUDIT = "AUDIT"
    SECURITY_LOG = "SECURITY_LOG"
    ERROR_LOG = "ERROR_LOG"
    OPS_LOG = "OPS_LOG"
    TELEMETRY = "TELEMETRY"
    RUNTIME_STATE = "RUNTIME_STATE"
    CONFIG = "CONFIG"
    MODULES = "MODULES"
    JOB_ARTIFACT = "JOB_ARTIFACT"
    TRANSCRIPT = "TRANSCRIPT"
    MEMORY = "MEMORY"


class Sensitivity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    SPECIAL = "SPECIAL"


class LawfulBasis(str, Enum):
    CONSENT = "CONSENT"
    CONTRACT = "CONTRACT"
    LEGAL_OBLIGATION = "LEGAL_OBLIGATION"
    VITAL_INTERESTS = "VITAL_INTERESTS"
    PUBLIC_TASK = "PUBLIC_TASK"
    LEGITIMATE_INTERESTS = "LEGITIMATE_INTERESTS"


class StorageKind(str, Enum):
    FILE = "FILE"
    SQLITE = "SQLITE"
    OTHER = "OTHER"


class DsarRequestType(str, Enum):
    ACCESS = "ACCESS"
    EXPORT = "EXPORT"
    DELETE = "DELETE"
    CORRECT = "CORRECT"
    RESTRICT = "RESTRICT"


class DsarStatus(str, Enum):
    OPEN = "OPEN"
    IN_PROGRESS = "IN_PROGRESS"
    COMPLETED = "COMPLETED"
    REJECTED = "REJECTED"


class UserIdentity(BaseModel):
    model_config = ConfigDict(extra="forbid")

    user_id: str = Field(min_length=1, max_length=64)
    display_name: str = Field(default="", max_length=120)
    created_at: str = Field(default_factory=_iso_now)
    is_default: bool = False


class RetentionPolicy(BaseModel):
    """
    Policy applied to a DataRecord at write time.
    """

    model_config = ConfigDict(extra="forbid")

    policy_id: str = Field(default="", max_length=80)
    data_category: DataCategory
    sensitivity: Sensitivity
    ttl_days: Optional[int] = Field(default=None, ge=1, le=3650)
    keep_forever: bool = False
    deletion_action: str = Field(default="delete", max_length=40)  # delete|anonymize|archive_encrypted
    review_required: bool = False

    def resolve_expires_at(self, *, created_at: str) -> Optional[str]:
        if self.keep_forever:
            return None
        if not self.ttl_days:
            return None
        # created_at is ISO8601 UTC (YYYY-mm-ddTHH:MM:SSZ) as used elsewhere in Jarvis logs.
        try:
            # Parse manually to avoid non-stdlib deps.
            import calendar

            ts = time.strptime(created_at, "%Y-%m-%dT%H:%M:%SZ")
            created_epoch = int(calendar.timegm(ts))
        except Exception:
            created_epoch = int(time.time())
        expires_epoch = created_epoch + int(self.ttl_days) * 86400
        return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(expires_epoch))


class ConsentRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")

    consent_id: str = Field(default_factory=lambda: uuid.uuid4().hex)
    user_id: str = Field(min_length=1, max_length=64)
    scope: str = Field(min_length=1, max_length=80)
    granted: bool = False
    recorded_at: str = Field(default_factory=_iso_now)
    lawful_basis: LawfulBasis = LawfulBasis.CONSENT
    evidence: str = Field(default="", max_length=200)


class PrivacyPreferences(BaseModel):
    """
    Core privacy toggles (per-user).

    NOTE:
    `network_allowed_non_admin` is intentionally immutable false in core logic;
    policy/capabilities are the enforcement source of truth.
    """

    model_config = ConfigDict(extra="forbid")

    user_id: str = Field(min_length=1, max_length=64, default="default")
    memory_enabled: bool = False
    transcript_retention_days: int = Field(default=0, ge=0, le=3650)
    network_allowed_non_admin: bool = False


class DSARRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    request_id: str = Field(default_factory=lambda: uuid.uuid4().hex)
    user_id: str = Field(min_length=1, max_length=64)
    request_type: DsarRequestType
    status: DsarStatus = DsarStatus.OPEN
    created_at: str = Field(default_factory=_iso_now)
    completed_at: Optional[str] = None
    notes: str = Field(default="", max_length=200)
    # Persisted as JSON strings in sqlite. Never include raw conversation content by default.
    payload: Dict[str, Any] = Field(default_factory=dict)
    result: Dict[str, Any] = Field(default_factory=dict)
    export_path: Optional[str] = None


class DataRecord(BaseModel):
    """
    Privacy-safe inventory entry for a persistent artifact.

    IMPORTANT:
    - store *references* only (paths/keys), never raw content.
    - safe to include in audit logs (after redaction).
    """

    model_config = ConfigDict(extra="forbid")

    record_id: str = Field(default="", max_length=64)
    user_id: str = Field(min_length=1, max_length=64, default="default")
    data_category: DataCategory
    sensitivity: Sensitivity = Sensitivity.LOW
    lawful_basis: LawfulBasis = LawfulBasis.LEGITIMATE_INTERESTS

    created_at: str = Field(default_factory=_iso_now)
    expires_at: Optional[str] = None

    storage_kind: StorageKind = StorageKind.FILE
    storage_ref: str = Field(min_length=1, max_length=512)  # path, table name, object key, etc.
    storage_ref_hash: str = Field(default="", max_length=64)
    size_bytes: Optional[int] = Field(default=None, ge=0)

    trace_id: Optional[str] = Field(default=None, max_length=64)
    producer: str = Field(default="core", max_length=80)
    tags: Dict[str, str] = Field(default_factory=dict)

    # For explicitness in tests and code review: content is NEVER included.
    content_present: bool = False

    @field_validator("record_id", mode="before")
    @classmethod
    def _default_record_id(cls, v: Any, info) -> str:  # noqa: ANN001
        if v:
            return str(v)
        # Deterministic-ish id based on category+storage_ref hash (computed later) is set by store if missing.
        return ""

    @field_validator("tags", mode="before")
    @classmethod
    def _tags_sanitize(cls, v: Any) -> Dict[str, str]:
        if v is None:
            return {}
        if not isinstance(v, dict):
            return {}
        out: Dict[str, str] = {}
        for k, val in v.items():
            kk = str(k or "").strip()
            if not kk:
                continue
            # never allow suspicious keys that often carry raw content
            if kk.lower() in {"content", "text", "raw", "prompt", "message", "messages"}:
                continue
            vv = str(val or "").strip()
            if not vv:
                continue
            out[kk[:64]] = vv[:120]
        return out

    @field_validator("content_present")
    @classmethod
    def _must_be_false(cls, v: Any) -> bool:
        # If any code tries to toggle this, that's a sign it wants to store content here: block it.
        return False


class PrivacyConfigFile(BaseModel):
    """
    config/privacy.json schema.

    This file is validated by ConfigManager similarly to capabilities.json:
    it is strict, but not embedded into the main AppConfigV2 model to keep
    the core config schema lean.
    """

    model_config = ConfigDict(extra="forbid")

    enabled: bool = True
    schema_version: int = Field(default=1, ge=1, le=10)
    default_user_id: str = Field(default="default", min_length=1, max_length=64)
    data_minimization: Dict[str, Any] = Field(
        default_factory=lambda: {
            "disable_persistent_user_text": True,
            "disable_persistent_raw_prompts": True,
            "disable_persistent_transcripts": True,
        }
    )
    default_consent_scopes: Dict[str, bool] = Field(default_factory=lambda: {"telemetry": True, "crash_reports": True, "memory": False, "transcripts": False})
    dsar: Dict[str, Any] = Field(
        default_factory=lambda: {
            "export": {"allow_copy_categories": [], "include_redacted_logs": True},
            "delete": {"categories": ["JOB_ARTIFACT"], "deletion_action": "delete"},
            "restrict": {"default_scopes": ["memory"]},
        }
    )
    retention_policies: List[Dict[str, Any]] = Field(
        default_factory=lambda: [
            {"data_category": "AUDIT", "sensitivity": "LOW", "ttl_days": 90, "deletion_action": "delete", "review_required": True},
            {"data_category": "SECURITY_LOG", "sensitivity": "LOW", "ttl_days": 30, "deletion_action": "delete", "review_required": False},
            {"data_category": "ERROR_LOG", "sensitivity": "LOW", "ttl_days": 30, "deletion_action": "delete", "review_required": False},
            {"data_category": "OPS_LOG", "sensitivity": "LOW", "ttl_days": 30, "deletion_action": "delete", "review_required": False},
            {"data_category": "TELEMETRY", "sensitivity": "LOW", "ttl_days": 14, "deletion_action": "delete", "review_required": False},
            {"data_category": "RUNTIME_STATE", "sensitivity": "LOW", "ttl_days": 90, "deletion_action": "delete", "review_required": False},
            {"data_category": "CONFIG", "sensitivity": "LOW", "ttl_days": 365, "deletion_action": "delete", "review_required": True},
            {"data_category": "MODULES", "sensitivity": "LOW", "ttl_days": 90, "deletion_action": "delete", "review_required": False},
            {"data_category": "JOB_ARTIFACT", "sensitivity": "MEDIUM", "ttl_days": 30, "deletion_action": "delete", "review_required": True},
            {"data_category": "TRANSCRIPT", "sensitivity": "HIGH", "ttl_days": 7, "deletion_action": "delete", "review_required": False},
            {"data_category": "MEMORY", "sensitivity": "HIGH", "ttl_days": 30, "deletion_action": "delete", "review_required": True},
        ]
    )


def default_privacy_config_dict() -> Dict[str, Any]:
    return PrivacyConfigFile().model_dump()

