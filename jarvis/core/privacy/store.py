from __future__ import annotations

import json
import os
import sqlite3
import threading
import uuid
from typing import Any, Dict, Iterable, List, Optional

from jarvis.core.events.models import BaseEvent, EventSeverity, SourceSubsystem
from jarvis.core.privacy.models import (
    ConsentRecord,
    DataCategory,
    DataRecord,
    DSARRequest,
    LawfulBasis,
    PrivacyPreferences,
    PrivacyConfigFile,
    RetentionPolicy,
    Sensitivity,
    UserIdentity,
    default_privacy_config_dict,
)
from jarvis.core.privacy.tagging import data_record_for_sqlite


class PrivacyStore:
    """
    Local privacy inventory store (SQLite).

    NOTES:
    - stdlib sqlite3 is Windows-safe
    - store does not contain raw user text/content; only references and metadata
    """

    SENSITIVE_SCOPES = {"memory", "transcripts"}

    def __init__(self, *, db_path: str, config_manager: Any = None, event_bus: Any = None, logger: Any = None):
        self.db_path = str(db_path)
        self.config = config_manager
        self.event_bus = event_bus
        self.logger = logger
        self._lock = threading.Lock()
        os.makedirs(os.path.dirname(self.db_path) or ".", exist_ok=True)
        self._init_db()

        # Always ensure a default user exists for single-user mode.
        try:
            self.get_or_create_default_user()
        except Exception:
            pass

        # Ensure default preferences exist (single-user mode).
        try:
            _ = self.get_preferences(user_id="default")
        except Exception:
            pass

    def attach_event_bus(self, event_bus: Any) -> None:
        self.event_bus = event_bus

    # ---- sqlite helpers ----
    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        try:
            conn.execute("PRAGMA journal_mode=WAL;")
            conn.execute("PRAGMA synchronous=NORMAL;")
        except Exception:
            pass
        return conn

    def _init_db(self) -> None:
        with self._lock:
            conn = self._conn()
            try:
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS users (
                      user_id TEXT PRIMARY KEY,
                      display_name TEXT,
                      created_at TEXT,
                      is_default INTEGER
                    )
                    """
                )
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS data_records (
                      record_id TEXT PRIMARY KEY,
                      user_id TEXT,
                      data_category TEXT,
                      sensitivity TEXT,
                      lawful_basis TEXT,
                      created_at TEXT,
                      expires_at TEXT,
                      storage_ref TEXT,
                      storage_ref_hash TEXT,
                      size_bytes INTEGER,
                      storage_kind TEXT,
                      trace_id TEXT,
                      producer TEXT,
                      tags_json TEXT,
                      content_present INTEGER,
                      last_seen_at TEXT
                    )
                    """
                )
                conn.execute("CREATE INDEX IF NOT EXISTS idx_data_records_user ON data_records(user_id)")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_data_records_expires ON data_records(expires_at)")

                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS consents (
                      consent_id TEXT PRIMARY KEY,
                      user_id TEXT,
                      scope TEXT,
                      granted INTEGER,
                      recorded_at TEXT,
                      lawful_basis TEXT,
                      evidence TEXT
                    )
                    """
                )
                conn.execute("CREATE INDEX IF NOT EXISTS idx_consents_user_scope ON consents(user_id, scope)")
                # Ensure one row per (user_id, scope) so grant/revoke is deterministic.
                conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_consents_user_scope_unique ON consents(user_id, scope)")

                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS preferences (
                      user_id TEXT PRIMARY KEY,
                      memory_enabled INTEGER,
                      transcript_retention_days INTEGER,
                      network_allowed_non_admin INTEGER,
                      updated_at TEXT
                    )
                    """
                )

                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS dsar_requests (
                      request_id TEXT PRIMARY KEY,
                      user_id TEXT,
                      request_type TEXT,
                      status TEXT,
                      created_at TEXT,
                      completed_at TEXT,
                      notes TEXT
                    )
                    """
                )
                conn.execute("CREATE INDEX IF NOT EXISTS idx_dsar_user ON dsar_requests(user_id)")
                conn.commit()
            finally:
                conn.close()

    # ---- internal emit ----
    def _emit(self, trace_id: str, event_type: str, payload: Dict[str, Any], *, severity: EventSeverity = EventSeverity.INFO) -> None:
        if self.event_bus is None:
            return
        try:
            self.event_bus.publish_nowait(
                BaseEvent(
                    event_type=str(event_type),
                    trace_id=str(trace_id or "privacy"),
                    source_subsystem=SourceSubsystem.audit,
                    severity=severity,
                    payload=dict(payload or {}),
                )
            )
        except Exception:
            pass

    # ---- config / retention ----
    def _privacy_cfg_raw(self) -> Dict[str, Any]:
        if self.config is None:
            return default_privacy_config_dict()
        try:
            raw = self.config.read_non_sensitive("privacy.json") or {}
        except Exception:
            raw = {}
        if not isinstance(raw, dict) or not raw:
            raw = default_privacy_config_dict()
        # validate (strict); fallback to defaults if invalid to avoid breaking core
        try:
            _ = PrivacyConfigFile.model_validate(raw)
        except Exception:
            raw = default_privacy_config_dict()
        return raw

    def resolve_retention_policy(self, *, data_category: DataCategory, sensitivity: Sensitivity) -> RetentionPolicy:
        raw = self._privacy_cfg_raw()
        policies = raw.get("retention_policies") or []
        if not isinstance(policies, list):
            policies = []
        best = None
        for p in policies:
            if not isinstance(p, dict):
                continue
            if str(p.get("data_category") or "").upper() != data_category.value:
                continue
            if str(p.get("sensitivity") or "").upper() != sensitivity.value:
                continue
            best = p
            break
        ttl = None
        keep_forever = False
        if isinstance(best, dict):
            ttl = best.get("ttl_days")
            keep_forever = bool(best.get("keep_forever", False))
        pol = RetentionPolicy(
            policy_id=f"{data_category.value}:{sensitivity.value}",
            data_category=data_category,
            sensitivity=sensitivity,
            ttl_days=int(ttl) if ttl else None,
            keep_forever=keep_forever,
        )
        return pol

    # ---- users ----
    def get_or_create_default_user(self) -> UserIdentity:
        raw = self._privacy_cfg_raw()
        default_user_id = str(raw.get("default_user_id") or "default")
        return self.get_or_create_user(user_id=default_user_id, display_name="Default", is_default=True)

    def get_or_create_user(self, *, user_id: str, display_name: str = "", is_default: bool = False) -> UserIdentity:
        uid = str(user_id or "default")[:64]
        with self._lock:
            conn = self._conn()
            try:
                row = conn.execute("SELECT user_id, display_name, created_at, is_default FROM users WHERE user_id=?", (uid,)).fetchone()
                if row:
                    return UserIdentity(user_id=row["user_id"], display_name=row["display_name"] or "", created_at=row["created_at"] or "", is_default=bool(row["is_default"]))
                user = UserIdentity(user_id=uid, display_name=str(display_name or "")[:120], is_default=bool(is_default))
                conn.execute(
                    "INSERT INTO users(user_id, display_name, created_at, is_default) VALUES (?, ?, ?, ?)",
                    (user.user_id, user.display_name, user.created_at, 1 if user.is_default else 0),
                )
                conn.commit()
                return user
            finally:
                conn.close()

    # ---- preferences ----
    def get_preferences(self, *, user_id: str = "default") -> PrivacyPreferences:
        uid = str(user_id or "default")[:64]
        _ = self.get_or_create_user(user_id=uid, display_name="", is_default=(uid == "default"))
        with self._lock:
            conn = self._conn()
            try:
                row = conn.execute("SELECT user_id, memory_enabled, transcript_retention_days, network_allowed_non_admin FROM preferences WHERE user_id=?", (uid,)).fetchone()
                if row:
                    return PrivacyPreferences(
                        user_id=row["user_id"],
                        memory_enabled=bool(row["memory_enabled"]),
                        transcript_retention_days=int(row["transcript_retention_days"] or 0),
                        network_allowed_non_admin=False,  # immutable false
                    )
                prefs = PrivacyPreferences(user_id=uid, memory_enabled=False, transcript_retention_days=0, network_allowed_non_admin=False)
                conn.execute(
                    "INSERT INTO preferences(user_id, memory_enabled, transcript_retention_days, network_allowed_non_admin, updated_at) VALUES (?, ?, ?, ?, strftime('%Y-%m-%dT%H:%M:%SZ','now'))",
                    (prefs.user_id, 1 if prefs.memory_enabled else 0, int(prefs.transcript_retention_days), 0),
                )
                conn.commit()
                return prefs
            finally:
                conn.close()

    def _update_preferences(
        self,
        *,
        user_id: str,
        memory_enabled: Optional[bool] = None,
        transcript_retention_days: Optional[int] = None,
    ) -> PrivacyPreferences:
        uid = str(user_id or "default")[:64]
        cur = self.get_preferences(user_id=uid)
        mem = bool(cur.memory_enabled) if memory_enabled is None else bool(memory_enabled)
        trd = int(cur.transcript_retention_days) if transcript_retention_days is None else max(0, int(transcript_retention_days))
        with self._lock:
            conn = self._conn()
            try:
                conn.execute(
                    "INSERT INTO preferences(user_id, memory_enabled, transcript_retention_days, network_allowed_non_admin, updated_at) VALUES (?, ?, ?, ?, strftime('%Y-%m-%dT%H:%M:%SZ','now')) "
                    "ON CONFLICT(user_id) DO UPDATE SET memory_enabled=excluded.memory_enabled, transcript_retention_days=excluded.transcript_retention_days, network_allowed_non_admin=0, updated_at=excluded.updated_at",
                    (uid, 1 if mem else 0, int(trd), 0),
                )
                conn.commit()
            finally:
                conn.close()
        return PrivacyPreferences(user_id=uid, memory_enabled=mem, transcript_retention_days=trd, network_allowed_non_admin=False)

    # ---- data records ----
    def register_record(self, rec: DataRecord) -> str:
        """
        Register a new persistent artifact reference.

        Security / privacy:
        - never stores raw content
        - safe to call frequently (upsert-ish behavior)
        """
        if not isinstance(rec, DataRecord):
            rec = DataRecord.model_validate(rec)

        # Ensure user exists
        _ = self.get_or_create_user(user_id=rec.user_id, display_name="", is_default=(rec.user_id == "default"))

        # Apply retention if not already set
        expires_at = rec.expires_at
        if expires_at is None:
            pol = self.resolve_retention_policy(data_category=rec.data_category, sensitivity=rec.sensitivity)
            expires_at = pol.resolve_expires_at(created_at=rec.created_at)

        record_id = rec.record_id or self._derive_record_id(rec)
        tags_json = json.dumps(dict(rec.tags or {}), ensure_ascii=False, sort_keys=True)

        with self._lock:
            conn = self._conn()
            try:
                conn.execute(
                    """
                    INSERT INTO data_records(
                      record_id, user_id, data_category, sensitivity, lawful_basis,
                      created_at, expires_at, storage_ref, storage_ref_hash,
                      size_bytes, storage_kind, trace_id, producer, tags_json,
                      content_present, last_seen_at
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(record_id) DO UPDATE SET
                      last_seen_at=excluded.last_seen_at,
                      expires_at=COALESCE(excluded.expires_at, data_records.expires_at),
                      size_bytes=COALESCE(excluded.size_bytes, data_records.size_bytes),
                      tags_json=excluded.tags_json
                    """,
                    (
                        record_id,
                        rec.user_id,
                        rec.data_category.value,
                        rec.sensitivity.value,
                        rec.lawful_basis.value,
                        rec.created_at,
                        expires_at,
                        rec.storage_ref,
                        rec.storage_ref_hash,
                        rec.size_bytes,
                        rec.storage_kind.value,
                        rec.trace_id,
                        rec.producer,
                        tags_json,
                        0,
                        rec.created_at,
                    ),
                )
                conn.commit()
            finally:
                conn.close()

        self._emit(
            str(rec.trace_id or "privacy"),
            "privacy.data_record_registered",
            {
                "record_id": record_id,
                "user_id": rec.user_id,
                "data_category": rec.data_category.value,
                "sensitivity": rec.sensitivity.value,
                "lawful_basis": rec.lawful_basis.value,
                "storage_kind": rec.storage_kind.value,
                "storage_ref_hash": rec.storage_ref_hash[:12],
            },
        )

        return record_id

    def list_records(self, *, user_id: str = "default", limit: int = 200) -> List[DataRecord]:
        uid = str(user_id or "default")
        with self._lock:
            conn = self._conn()
            try:
                rows = conn.execute(
                    "SELECT * FROM data_records WHERE user_id=? ORDER BY created_at DESC LIMIT ?",
                    (uid, max(1, int(limit))),
                ).fetchall()
            finally:
                conn.close()
        out: List[DataRecord] = []
        for r in rows or []:
            try:
                tags = json.loads(r["tags_json"] or "{}")
            except Exception:
                tags = {}
            out.append(
                DataRecord(
                    record_id=r["record_id"],
                    user_id=r["user_id"],
                    data_category=DataCategory(str(r["data_category"])),
                    sensitivity=Sensitivity(str(r["sensitivity"])),
                    lawful_basis=LawfulBasis(str(r["lawful_basis"])),
                    created_at=str(r["created_at"] or ""),
                    expires_at=r["expires_at"],
                    storage_ref=str(r["storage_ref"] or ""),
                    storage_ref_hash=str(r["storage_ref_hash"] or ""),
                    size_bytes=r["size_bytes"],
                    storage_kind=str(r["storage_kind"] or "FILE"),
                    trace_id=r["trace_id"],
                    producer=str(r["producer"] or "core"),
                    tags={str(k): str(v) for k, v in (tags or {}).items() if k and v},
                    content_present=False,
                )
            )
        return out

    def _derive_record_id(self, rec: DataRecord) -> str:
        # Stable-ish derived id to avoid duplicates for the same artifact in one run.
        # Use uuid5 over a safe, non-content namespace string.
        base = f"{rec.user_id}|{rec.data_category.value}|{rec.storage_kind.value}|{rec.storage_ref_hash or rec.storage_ref}"
        return uuid.uuid5(uuid.NAMESPACE_URL, base).hex

    # ---- consents ----
    def upsert_consent(self, rec: ConsentRecord) -> str:
        if not isinstance(rec, ConsentRecord):
            rec = ConsentRecord.model_validate(rec)
        _ = self.get_or_create_user(user_id=rec.user_id, display_name="", is_default=(rec.user_id == "default"))
        with self._lock:
            conn = self._conn()
            try:
                conn.execute(
                    """
                    INSERT INTO consents(consent_id, user_id, scope, granted, recorded_at, lawful_basis, evidence)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    ON CONFLICT(user_id, scope) DO UPDATE SET
                      granted=excluded.granted,
                      recorded_at=excluded.recorded_at,
                      lawful_basis=excluded.lawful_basis,
                      evidence=excluded.evidence
                    """,
                    (rec.consent_id, rec.user_id, rec.scope, 1 if rec.granted else 0, rec.recorded_at, rec.lawful_basis.value, rec.evidence),
                )
                conn.commit()
            finally:
                conn.close()
        # Update preferences for core toggles tied to consent
        if rec.scope.lower() == "memory":
            _ = self._update_preferences(user_id=rec.user_id, memory_enabled=bool(rec.granted))
        if rec.scope.lower() == "transcripts":
            # granting transcript storage implies a non-zero retention default; revoking sets to 0
            _ = self._update_preferences(user_id=rec.user_id, transcript_retention_days=(30 if rec.granted else 0))

        return rec.consent_id

    def get_consent(self, *, user_id: str = "default", scope: str) -> Optional[ConsentRecord]:
        uid = str(user_id or "default")[:64]
        sc = str(scope or "").strip()
        if not sc:
            return None
        with self._lock:
            conn = self._conn()
            try:
                row = conn.execute(
                    "SELECT consent_id, user_id, scope, granted, recorded_at, lawful_basis, evidence FROM consents WHERE user_id=? AND scope=? ORDER BY recorded_at DESC LIMIT 1",
                    (uid, sc),
                ).fetchone()
            finally:
                conn.close()
        if not row:
            return None
        return ConsentRecord(
            consent_id=row["consent_id"],
            user_id=row["user_id"],
            scope=row["scope"],
            granted=bool(row["granted"]),
            recorded_at=row["recorded_at"] or "",
            lawful_basis=LawfulBasis(str(row["lawful_basis"] or "CONSENT")),
            evidence=str(row["evidence"] or ""),
        )

    def set_consent(self, *, user_id: str = "default", scope: str, granted: bool, trace_id: str = "privacy", actor_is_admin: bool = False) -> bool:
        """
        Grant/revoke consent by scope.
        Admin required for sensitive scopes (memory/transcripts).
        """
        sc = str(scope or "").strip().lower()
        if not sc:
            return False
        if sc in self.SENSITIVE_SCOPES and not bool(actor_is_admin):
            self._emit(str(trace_id), "privacy.consent_change_denied", {"user_id": str(user_id), "scope": sc, "reason": "admin_required"}, severity=EventSeverity.WARN)
            return False
        rec = ConsentRecord(user_id=str(user_id or "default"), scope=sc, granted=bool(granted), evidence="cli/admin" if actor_is_admin else "cli")
        _ = self.upsert_consent(rec)
        self._emit(
            str(trace_id),
            "privacy.consent_changed",
            {"user_id": rec.user_id, "scope": rec.scope, "granted": bool(rec.granted), "lawful_basis": rec.lawful_basis.value},
            severity=EventSeverity.INFO,
        )
        return True

    # ---- retention config mutation (admin-only) ----
    def list_retention_policies(self) -> List[Dict[str, Any]]:
        raw = self._privacy_cfg_raw()
        out = raw.get("retention_policies") or []
        return out if isinstance(out, list) else []

    def set_retention_ttl_days(self, *, policy_id: str, ttl_days: int, trace_id: str = "privacy", actor_is_admin: bool = False) -> bool:
        """
        Update config/privacy.json retention policy ttl_days.
        Admin-only (CAP_ADMIN_ACTION semantics).
        """
        if not bool(actor_is_admin):
            self._emit(str(trace_id), "privacy.retention_change_denied", {"policy_id": str(policy_id), "reason": "admin_required"}, severity=EventSeverity.WARN)
            raise PermissionError("Admin required (CAP_ADMIN_ACTION).")
        pid = str(policy_id or "").strip()
        if not pid or ":" not in pid:
            return False
        cat, sens = pid.split(":", 1)
        cat = cat.strip().upper()
        sens = sens.strip().upper()
        ttl = max(1, int(ttl_days))
        if self.config is None:
            return False
        raw = self.config.read_non_sensitive("privacy.json") or {}
        if not isinstance(raw, dict):
            raw = {}
        raw.setdefault("schema_version", 1)
        raw.setdefault("default_user_id", "default")
        raw.setdefault("data_minimization", {})
        raw.setdefault("default_consent_scopes", {})
        pols = raw.get("retention_policies") or []
        if not isinstance(pols, list):
            pols = []
        found = False
        for p in pols:
            if not isinstance(p, dict):
                continue
            if str(p.get("data_category") or "").upper() == cat and str(p.get("sensitivity") or "").upper() == sens:
                p["ttl_days"] = ttl
                p.pop("keep_forever", None)
                found = True
                break
        if not found:
            pols.append({"data_category": cat, "sensitivity": sens, "ttl_days": ttl})
        raw["retention_policies"] = pols
        # Validate + write through ConfigManager (atomic + validated)
        self.config.save_non_sensitive("privacy.json", raw)
        self._emit(str(trace_id), "privacy.retention_updated", {"policy_id": pid, "ttl_days": ttl, "actor": "admin"}, severity=EventSeverity.WARN)
        return True

    # ---- dsar ----
    def create_dsar(self, req: DSARRequest) -> str:
        if not isinstance(req, DSARRequest):
            req = DSARRequest.model_validate(req)
        _ = self.get_or_create_user(user_id=req.user_id, display_name="", is_default=(req.user_id == "default"))
        with self._lock:
            conn = self._conn()
            try:
                conn.execute(
                    "INSERT INTO dsar_requests(request_id, user_id, request_type, status, created_at, completed_at, notes) VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (req.request_id, req.user_id, req.request_type.value, req.status.value, req.created_at, req.completed_at, req.notes),
                )
                conn.commit()
            finally:
                conn.close()
        return req.request_id

