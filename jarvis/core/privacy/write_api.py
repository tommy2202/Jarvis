from __future__ import annotations

import hashlib
import time
import uuid
from enum import Enum
from typing import Any, Dict, Optional

from pydantic import BaseModel, ConfigDict, Field

from jarvis.core.privacy.gates import persist_allowed_current
from jarvis.core.privacy.models import (
    DataCategory,
    DataRecord,
    LawfulBasis,
    Sensitivity,
    StorageKind,
)
from jarvis.core.privacy.redaction import privacy_redact
from jarvis.core.security_events import SecurityAuditLogger


class WriteAction(str, Enum):
    memory = "memory"
    artifact_metadata = "artifact_metadata"
    user_log = "user_log"


class WriteRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    action: WriteAction
    trace_id: str
    user_id: str = "default"
    data_category: DataCategory
    sensitivity: Sensitivity = Sensitivity.LOW
    lawful_basis: LawfulBasis = LawfulBasis.LEGITIMATE_INTERESTS
    storage_kind: StorageKind = StorageKind.OTHER
    storage_ref: str = ""
    storage_ref_hash: str = ""
    size_bytes: Optional[int] = None
    tags: Dict[str, str] = Field(default_factory=dict)
    scope: Optional[str] = None
    ephemeral: Optional[bool] = None
    metadata_only: bool = False


class WriteDecision(BaseModel):
    model_config = ConfigDict(extra="forbid")

    allowed: bool
    reason_code: str
    trace_id: str
    record_id: Optional[str] = None
    details: Dict[str, Any] = Field(default_factory=dict)


ALLOWED_EPHEMERAL_METADATA_CATEGORIES = {
    DataCategory.AUDIT,
    DataCategory.SECURITY_LOG,
    DataCategory.ERROR_LOG,
    DataCategory.OPS_LOG,
    DataCategory.TELEMETRY,
    DataCategory.CONFIG,
    DataCategory.MODULES,
    DataCategory.RUNTIME_STATE,
}


def allow_ephemeral_metadata_category(category: DataCategory) -> bool:
    return category in ALLOWED_EPHEMERAL_METADATA_CATEGORIES


def _now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _hash_ref(ref: str) -> str:
    if not ref:
        return ""
    return hashlib.sha256(ref.encode("utf-8", errors="ignore")).hexdigest()


def _is_ephemeral(req: WriteRequest) -> bool:
    if req.ephemeral is not None:
        return bool(req.ephemeral)
    return not bool(persist_allowed_current())


def _audit_decision(*, req: WriteRequest, decision: WriteDecision, audit_logger: Optional[SecurityAuditLogger]) -> None:
    if audit_logger is None:
        return
    details = {
        "action": req.action.value,
        "allowed": bool(decision.allowed),
        "reason_code": str(decision.reason_code or ""),
        "data_category": req.data_category.value,
        "sensitivity": req.sensitivity.value,
        "lawful_basis": req.lawful_basis.value,
        "scope": str(req.scope or ""),
        "storage_kind": req.storage_kind.value,
        "storage_ref_hash": str(req.storage_ref_hash or ""),
        "size_bytes": int(req.size_bytes) if req.size_bytes is not None else None,
        "tags": sorted(list((req.tags or {}).keys()))[:50],
    }
    audit_logger.log(
        trace_id=req.trace_id,
        severity="INFO" if decision.allowed else "WARN",
        event="privacy.write",
        ip=None,
        endpoint=str(req.action.value),
        outcome="allowed" if decision.allowed else "denied",
        details=privacy_redact(details),
    )


def _deny(trace_id: str, reason_code: str, *, details: Optional[Dict[str, Any]] = None) -> WriteDecision:
    return WriteDecision(allowed=False, reason_code=str(reason_code), trace_id=str(trace_id), details=details or {})


def _allow(trace_id: str, *, details: Optional[Dict[str, Any]] = None) -> WriteDecision:
    return WriteDecision(allowed=True, reason_code="allowed", trace_id=str(trace_id), details=details or {})


def _decide_write(*, req: WriteRequest, privacy_store) -> WriteDecision:
    if privacy_store is None:
        return _deny(req.trace_id, "privacy_store_missing")

    ephemeral = _is_ephemeral(req)
    if ephemeral:
        if not (req.metadata_only and allow_ephemeral_metadata_category(req.data_category)):
            return _deny(req.trace_id, "ephemeral_mode")

    # Config gates (data minimization)
    try:
        cfg = privacy_store._privacy_cfg_raw()  # noqa: SLF001
        dm = (cfg.get("data_minimization") or {}) if isinstance(cfg, dict) else {}
        if req.action == WriteAction.memory and bool(dm.get("disable_persistent_user_text", True)):
            return _deny(req.trace_id, "config_disabled")
        if req.action == WriteAction.user_log and req.scope == "transcripts" and bool(dm.get("disable_persistent_transcripts", True)):
            return _deny(req.trace_id, "config_disabled")
    except Exception:
        return _deny(req.trace_id, "config_invalid")

    # Consent / restriction gates
    if req.scope:
        try:
            if bool(getattr(privacy_store, "is_scope_restricted")(user_id=req.user_id, scope=req.scope)):
                return _deny(req.trace_id, "scope_restricted")
        except Exception:
            return _deny(req.trace_id, "scope_check_failed")
        try:
            c = privacy_store.get_consent(user_id=req.user_id, scope=req.scope)
            if not (c and bool(getattr(c, "granted", False))):
                return _deny(req.trace_id, "consent_missing")
        except Exception:
            return _deny(req.trace_id, "consent_check_failed")

    return _allow(req.trace_id)


def write_artifact_metadata(
    *,
    privacy_store,
    record: DataRecord | Dict[str, Any],
    trace_id: str,
    audit_logger: Optional[SecurityAuditLogger] = None,
) -> WriteDecision:
    rec = record if isinstance(record, DataRecord) else DataRecord.model_validate(record)
    req = WriteRequest(
        action=WriteAction.artifact_metadata,
        trace_id=str(trace_id),
        user_id=str(rec.user_id or "default"),
        data_category=rec.data_category,
        sensitivity=rec.sensitivity,
        lawful_basis=rec.lawful_basis,
        storage_kind=rec.storage_kind,
        storage_ref=str(rec.storage_ref or ""),
        storage_ref_hash=str(rec.storage_ref_hash or ""),
        size_bytes=rec.size_bytes,
        tags=dict(rec.tags or {}),
        metadata_only=True,
    )
    if not req.storage_ref_hash:
        req.storage_ref_hash = _hash_ref(req.storage_ref)
    decision = _decide_write(req=req, privacy_store=privacy_store)
    if decision.allowed:
        try:
            record_id = privacy_store.register_record(rec)
            decision.record_id = str(record_id or "")
        except Exception:
            decision = _deny(trace_id, "record_write_failed")
    _audit_decision(req=req, decision=decision, audit_logger=audit_logger)
    return decision


def write_user_log(
    *,
    privacy_store,
    secure_store,
    trace_id: str,
    user_id: str,
    content: str,
    scope: str,
    data_category: DataCategory,
    sensitivity: Sensitivity,
    lawful_basis: LawfulBasis,
    producer: str,
    tags: Optional[Dict[str, str]] = None,
    audit_logger: Optional[SecurityAuditLogger] = None,
) -> WriteDecision:
    if not content:
        return _deny(trace_id, "empty_payload")
    key = f"{scope}:{trace_id}"
    req = WriteRequest(
        action=WriteAction.user_log,
        trace_id=str(trace_id),
        user_id=str(user_id or "default"),
        data_category=data_category,
        sensitivity=sensitivity,
        lawful_basis=lawful_basis,
        storage_kind=StorageKind.OTHER,
        storage_ref=f"secure_store:{key}",
        storage_ref_hash=_hash_ref(f"secure_store:{key}"),
        size_bytes=len(content),
        tags=dict(tags or {}),
        scope=str(scope or ""),
        metadata_only=False,
    )
    decision = _decide_write(req=req, privacy_store=privacy_store)
    if not decision.allowed:
        _audit_decision(req=req, decision=decision, audit_logger=audit_logger)
        return decision
    if secure_store is None:
        decision = _deny(trace_id, "secure_store_missing")
        _audit_decision(req=req, decision=decision, audit_logger=audit_logger)
        return decision
    try:
        secure_store.set(key, content, trace_id=str(trace_id))
    except Exception:
        decision = _deny(trace_id, "secure_store_write_failed")
        _audit_decision(req=req, decision=decision, audit_logger=audit_logger)
        return decision

    try:
        pol = privacy_store.resolve_retention_policy(data_category=data_category, sensitivity=sensitivity)
        expires = pol.resolve_expires_at(created_at=_now_iso())
    except Exception:
        expires = None

    try:
        rec = DataRecord(
            user_id=str(user_id or "default"),
            data_category=data_category,
            sensitivity=sensitivity,
            lawful_basis=lawful_basis,
            created_at=_now_iso(),
            expires_at=expires,
            storage_kind=StorageKind.OTHER,
            storage_ref=f"secure_store:{key}",
            storage_ref_hash=_hash_ref(f"secure_store:{key}"),
            trace_id=str(trace_id),
            producer=str(producer or "write_api"),
            tags=dict(tags or {}),
        )
        decision.record_id = str(privacy_store.register_record(rec) or "")
    except Exception:
        decision = _deny(trace_id, "record_write_failed")
    _audit_decision(req=req, decision=decision, audit_logger=audit_logger)
    return decision


def write_memory(
    *,
    privacy_store,
    secure_store,
    trace_id: str,
    user_id: str,
    content: str,
    tags: Optional[Dict[str, str]] = None,
    audit_logger: Optional[SecurityAuditLogger] = None,
) -> WriteDecision:
    if not content:
        return _deny(trace_id, "empty_payload")
    key = f"memory:{trace_id}:{uuid.uuid4().hex}"
    req = WriteRequest(
        action=WriteAction.memory,
        trace_id=str(trace_id),
        user_id=str(user_id or "default"),
        data_category=DataCategory.MEMORY,
        sensitivity=Sensitivity.HIGH,
        lawful_basis=LawfulBasis.CONSENT,
        storage_kind=StorageKind.OTHER,
        storage_ref=f"secure_store:{key}",
        storage_ref_hash=_hash_ref(f"secure_store:{key}"),
        size_bytes=len(content),
        tags=dict(tags or {}),
        scope="memory",
        metadata_only=False,
    )
    decision = _decide_write(req=req, privacy_store=privacy_store)
    if not decision.allowed:
        _audit_decision(req=req, decision=decision, audit_logger=audit_logger)
        return decision
    if secure_store is None:
        decision = _deny(trace_id, "secure_store_missing")
        _audit_decision(req=req, decision=decision, audit_logger=audit_logger)
        return decision
    try:
        secure_store.set(key, content, trace_id=str(trace_id))
    except Exception:
        decision = _deny(trace_id, "secure_store_write_failed")
        _audit_decision(req=req, decision=decision, audit_logger=audit_logger)
        return decision

    try:
        pol = privacy_store.resolve_retention_policy(data_category=DataCategory.MEMORY, sensitivity=Sensitivity.HIGH)
        expires = pol.resolve_expires_at(created_at=_now_iso())
    except Exception:
        expires = None

    try:
        rec = DataRecord(
            user_id=str(user_id or "default"),
            data_category=DataCategory.MEMORY,
            sensitivity=Sensitivity.HIGH,
            lawful_basis=LawfulBasis.CONSENT,
            created_at=_now_iso(),
            expires_at=expires,
            storage_kind=StorageKind.OTHER,
            storage_ref=f"secure_store:{key}",
            storage_ref_hash=_hash_ref(f"secure_store:{key}"),
            trace_id=str(trace_id),
            producer="write_api.memory",
            tags=dict(tags or {}),
        )
        decision.record_id = str(privacy_store.register_record(rec) or "")
    except Exception:
        decision = _deny(trace_id, "record_write_failed")
    _audit_decision(req=req, decision=decision, audit_logger=audit_logger)
    return decision
