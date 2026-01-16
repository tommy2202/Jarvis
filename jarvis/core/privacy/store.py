from __future__ import annotations

import json
import os
import sqlite3
import threading
import time
import uuid
from typing import Any, Dict, Iterable, List, Optional

from jarvis.core.events.models import BaseEvent, EventSeverity, SourceSubsystem
from jarvis.core.privacy.gates import persist_allowed_current
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

    def __init__(
        self,
        *,
        db_path: str,
        config_manager: Any = None,
        event_bus: Any = None,
        logger: Any = None,
        version_registry: Any = None,
        event_logger: Any = None,
    ):
        self.db_path = str(db_path)
        self.config = config_manager
        self.event_bus = event_bus
        self.logger = logger
        self.version_registry = version_registry
        self.event_logger = event_logger
        self.secure_store: Any = None
        self._lock = threading.Lock()
        os.makedirs(os.path.dirname(self.db_path) or ".", exist_ok=True)
        self._init_db()
        try:
            from jarvis.core.migrations.runner import run_privacy_store_migrations

            run_privacy_store_migrations(
                db_path=self.db_path,
                registry=self.version_registry,
                event_logger=self.event_logger,
                trace_id="privacy",
            )
        except Exception as e:
            if self.logger:
                self.logger.warning(f"Privacy migrations failed: {e}")

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

    def attach_secure_store(self, secure_store: Any) -> None:
        self.secure_store = secure_store

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

    def _ensure_column(self, *, conn: sqlite3.Connection, table: str, column: str, ddl: str) -> None:
        """
        Best-effort schema evolution for existing sqlite files.
        """
        try:
            cols = [r[1] for r in conn.execute(f"PRAGMA table_info({table})").fetchall()]
        except Exception:
            cols = []
        if column in cols:
            return
        try:
            conn.execute(f"ALTER TABLE {table} ADD COLUMN {ddl}")
        except Exception:
            pass

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
                # speed: retention queries
                conn.execute("CREATE INDEX IF NOT EXISTS idx_data_records_category ON data_records(data_category)")

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
                    CREATE TABLE IF NOT EXISTS retention_pending (
                      action_id TEXT PRIMARY KEY,
                      record_id TEXT,
                      user_id TEXT,
                      policy_id TEXT,
                      deletion_action TEXT,
                      created_at TEXT,
                      status TEXT,
                      decided_at TEXT,
                      decision TEXT,
                      error TEXT
                    )
                    """
                )
                conn.execute("CREATE INDEX IF NOT EXISTS idx_retention_pending_status ON retention_pending(status)")
                conn.execute("CREATE INDEX IF NOT EXISTS idx_retention_pending_record ON retention_pending(record_id)")

                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS dsar_requests (
                      request_id TEXT PRIMARY KEY,
                      user_id TEXT,
                      request_type TEXT,
                      status TEXT,
                      created_at TEXT,
                      completed_at TEXT,
                      notes TEXT,
                      payload_json TEXT,
                      result_json TEXT,
                      export_path TEXT
                    )
                    """
                )
                conn.execute("CREATE INDEX IF NOT EXISTS idx_dsar_user ON dsar_requests(user_id)")
                # ensure columns exist for older dbs
                self._ensure_column(conn=conn, table="dsar_requests", column="payload_json", ddl="payload_json TEXT")
                self._ensure_column(conn=conn, table="dsar_requests", column="result_json", ddl="result_json TEXT")
                self._ensure_column(conn=conn, table="dsar_requests", column="export_path", ddl="export_path TEXT")
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
        deletion_action = "delete"
        review_required = False
        if isinstance(best, dict):
            ttl = best.get("ttl_days")
            keep_forever = bool(best.get("keep_forever", False))
            deletion_action = str(best.get("deletion_action") or "delete").strip().lower()
            review_required = bool(best.get("review_required", False))
        if deletion_action not in {"delete", "anonymize", "archive_encrypted"}:
            deletion_action = "delete"
        pol = RetentionPolicy(
            policy_id=f"{data_category.value}:{sensitivity.value}",
            data_category=data_category,
            sensitivity=sensitivity,
            ttl_days=int(ttl) if ttl else None,
            keep_forever=keep_forever,
            deletion_action=deletion_action,
            review_required=review_required,
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

    def update_user_profile(self, *, user_id: str, display_name: Optional[str] = None) -> bool:
        uid = str(user_id or "default")[:64]
        _ = self.get_or_create_user(user_id=uid, display_name="", is_default=(uid == "default"))
        updates: Dict[str, Any] = {}
        if display_name is not None:
            updates["display_name"] = str(display_name or "")[:120]
        if not updates:
            return False
        with self._lock:
            conn = self._conn()
            try:
                conn.execute("UPDATE users SET display_name=? WHERE user_id=?", (updates["display_name"], uid))
                conn.commit()
            finally:
                conn.close()
        self._emit("privacy", "privacy.user_profile_updated", {"user_id": uid, "fields": list(updates.keys())}, severity=EventSeverity.INFO)
        return True

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

        # Global persistence gate (set by dispatcher via PrivacyGate).
        # If not allowed, do not persist inventory entries (ephemeral execution).
        if not bool(persist_allowed_current()):
            return rec.record_id or self._derive_record_id(rec)

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

    # ---- retention enforcement ----
    @staticmethod
    def _iso_now() -> str:
        return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    def _list_expired_record_rows(self, *, now_iso: str) -> List[sqlite3.Row]:
        with self._lock:
            conn = self._conn()
            try:
                rows = conn.execute(
                    """
                    SELECT * FROM data_records
                    WHERE expires_at IS NOT NULL
                      AND expires_at <= ?
                      AND data_category != ?
                      AND record_id NOT IN (SELECT record_id FROM retention_pending WHERE status='PENDING')
                    ORDER BY expires_at ASC
                    """,
                    (now_iso, DataCategory.AUDIT.value),
                ).fetchall()
            finally:
                conn.close()
        return list(rows or [])

    def retention_run(self, *, trace_id: str = "privacy", now_iso: Optional[str] = None) -> Dict[str, Any]:
        """
        Process expired records:
        - delete/anonymize/archive_encrypted (best-effort)
        - never touch audit timeline artifacts (append-only)
        - if policy requires review, create pending actions
        """
        now_iso = str(now_iso or self._iso_now())
        expired = self._list_expired_record_rows(now_iso=now_iso)
        deleted = 0
        anonymized = 0
        archived = 0
        pending = 0
        skipped = 0
        errors = 0

        for r in expired:
            try:
                cat = DataCategory(str(r["data_category"]))
                sens = Sensitivity(str(r["sensitivity"]))
            except Exception:
                skipped += 1
                continue
            pol = self.resolve_retention_policy(data_category=cat, sensitivity=sens)

            # hard rule: audit timeline is append-only and must not be deleted
            if cat == DataCategory.AUDIT or "logs/audit" in str(r["storage_ref"] or "").replace("\\", "/"):
                skipped += 1
                continue

            if bool(pol.review_required):
                if self._create_pending_action(
                    record_id=str(r["record_id"]),
                    user_id=str(r["user_id"] or "default"),
                    policy_id=str(pol.policy_id),
                    deletion_action=str(pol.deletion_action),
                ):
                    pending += 1
                else:
                    skipped += 1
                continue

            try:
                res = self._execute_deletion_action(row=r, deletion_action=str(pol.deletion_action))
                if res == "deleted":
                    deleted += 1
                elif res == "anonymized":
                    anonymized += 1
                elif res == "archived":
                    archived += 1
                elif res == "skipped":
                    skipped += 1
                else:
                    skipped += 1
            except Exception:
                errors += 1

        self._emit(
            str(trace_id or "privacy"),
            "retention.expired_handled",
            {
                "as_of": now_iso,
                "expired_found": len(expired),
                "deleted": deleted,
                "anonymized": anonymized,
                "archived": archived,
                "pending_review": pending,
                "skipped": skipped,
                "errors": errors,
            },
            severity=EventSeverity.INFO,
        )
        return {"ok": True, "as_of": now_iso, "expired_found": len(expired), "deleted": deleted, "anonymized": anonymized, "archived": archived, "pending_review": pending, "skipped": skipped, "errors": errors}

    def _create_pending_action(self, *, record_id: str, user_id: str, policy_id: str, deletion_action: str) -> bool:
        aid = uuid.uuid4().hex
        with self._lock:
            conn = self._conn()
            try:
                # idempotency: only one pending per record
                row = conn.execute("SELECT action_id FROM retention_pending WHERE record_id=? AND status='PENDING' LIMIT 1", (record_id,)).fetchone()
                if row:
                    return False
                conn.execute(
                    "INSERT INTO retention_pending(action_id, record_id, user_id, policy_id, deletion_action, created_at, status, decided_at, decision, error) VALUES (?, ?, ?, ?, ?, ?, 'PENDING', NULL, NULL, '')",
                    (aid, record_id, user_id, policy_id, deletion_action, self._iso_now()),
                )
                conn.commit()
            finally:
                conn.close()
        self._emit("privacy", "retention.review_required_created", {"action_id": aid, "record_id": record_id, "policy_id": policy_id, "deletion_action": deletion_action}, severity=EventSeverity.WARN)
        return True

    def retention_pending(self, *, limit: int = 200) -> List[Dict[str, Any]]:
        with self._lock:
            conn = self._conn()
            try:
                rows = conn.execute(
                    "SELECT action_id, record_id, user_id, policy_id, deletion_action, created_at, status FROM retention_pending WHERE status='PENDING' ORDER BY created_at ASC LIMIT ?",
                    (max(1, int(limit)),),
                ).fetchall()
            finally:
                conn.close()
        return [dict(r) for r in (rows or [])]

    def retention_approve(self, *, action_id: str, trace_id: str = "privacy", actor_is_admin: bool = False) -> bool:
        if not bool(actor_is_admin):
            raise PermissionError("Admin required (CAP_ADMIN_ACTION).")
        aid = str(action_id or "").strip()
        if not aid:
            return False
        with self._lock:
            conn = self._conn()
            try:
                row = conn.execute("SELECT * FROM retention_pending WHERE action_id=? AND status='PENDING'", (aid,)).fetchone()
                if not row:
                    return False
                rec = conn.execute("SELECT * FROM data_records WHERE record_id=?", (row["record_id"],)).fetchone()
                if not rec:
                    conn.execute("UPDATE retention_pending SET status='DONE', decided_at=?, decision='approved', error='' WHERE action_id=?", (self._iso_now(), aid))
                    conn.commit()
                    return True
            finally:
                conn.close()
        # execute outside lock (file ops)
        res = self._execute_deletion_action(row=rec, deletion_action=str(row["deletion_action"] or "delete"))
        with self._lock:
            conn2 = self._conn()
            try:
                conn2.execute("UPDATE retention_pending SET status='DONE', decided_at=?, decision='approved', error='' WHERE action_id=?", (self._iso_now(), aid))
                conn2.commit()
            finally:
                conn2.close()
        self._emit(str(trace_id or "privacy"), "retention.pending_approved", {"action_id": aid, "result": res}, severity=EventSeverity.WARN)
        return True

    def retention_deny(self, *, action_id: str, trace_id: str = "privacy", actor_is_admin: bool = False) -> bool:
        if not bool(actor_is_admin):
            raise PermissionError("Admin required (CAP_ADMIN_ACTION).")
        aid = str(action_id or "").strip()
        if not aid:
            return False
        with self._lock:
            conn = self._conn()
            try:
                row = conn.execute("SELECT action_id FROM retention_pending WHERE action_id=? AND status='PENDING'", (aid,)).fetchone()
                if not row:
                    return False
                conn.execute("UPDATE retention_pending SET status='DONE', decided_at=?, decision='denied', error='' WHERE action_id=?", (self._iso_now(), aid))
                conn.commit()
            finally:
                conn.close()
        self._emit(str(trace_id or "privacy"), "retention.pending_denied", {"action_id": aid}, severity=EventSeverity.WARN)
        return True

    def _execute_deletion_action(self, *, row: sqlite3.Row, deletion_action: str) -> str:
        action = str(deletion_action or "delete").strip().lower()
        sk = str(row["storage_kind"] or "FILE").upper()
        ref = str(row["storage_ref"] or "")
        ref_norm = ref.replace("\\", "/")

        # never delete audit timeline
        if "logs/audit" in ref_norm:
            return "skipped"

        if action == "archive_encrypted":
            # Placeholder: review-required policies should be used for this until encryption key mgmt is implemented.
            return "skipped"

        if action == "anonymize":
            if sk == "FILE" and ref_norm and os.path.exists(ref) and os.path.isfile(ref):
                try:
                    with open(ref, "w", encoding="utf-8") as f:
                        f.write("")
                    # remove inventory record reference
                    self._delete_data_record(record_id=str(row["record_id"]))
                    return "anonymized"
                except Exception:
                    return "skipped"
            self._delete_data_record(record_id=str(row["record_id"]))
            return "anonymized"

        # default: delete
        if sk == "OTHER" and ref_norm.startswith("secure_store:"):
            key = ref_norm.split("secure_store:", 1)[1]
            if self.secure_store is not None:
                try:
                    self.secure_store.delete(key, trace_id="privacy")
                except Exception:
                    pass
            self._delete_data_record(record_id=str(row["record_id"]))
            return "deleted"
        if sk == "FILE" and ref_norm and os.path.exists(ref) and os.path.isfile(ref):
            try:
                os.remove(ref)
            except Exception:
                # file missing/locked -> still remove reference so inventory doesn't keep stale pointers
                pass
        # For SQLITE/OTHER, deletion means deleting the referenced artifact is out of scope here; we drop reference.
        self._delete_data_record(record_id=str(row["record_id"]))
        return "deleted"

    def _delete_data_record(self, *, record_id: str) -> None:
        rid = str(record_id or "").strip()
        if not rid:
            return
        with self._lock:
            conn = self._conn()
            try:
                conn.execute("DELETE FROM data_records WHERE record_id=?", (rid,))
                conn.commit()
            finally:
                conn.close()

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
                    "INSERT INTO dsar_requests(request_id, user_id, request_type, status, created_at, completed_at, notes, payload_json, result_json, export_path) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        req.request_id,
                        req.user_id,
                        req.request_type.value,
                        req.status.value,
                        req.created_at,
                        req.completed_at,
                        req.notes,
                        json.dumps(dict(req.payload or {}), ensure_ascii=False),
                        json.dumps(dict(req.result or {}), ensure_ascii=False),
                        req.export_path,
                    ),
                )
                conn.commit()
            finally:
                conn.close()
        return req.request_id

    def get_dsar(self, request_id: str) -> Optional[DSARRequest]:
        rid = str(request_id or "").strip()
        if not rid:
            return None
        with self._lock:
            conn = self._conn()
            try:
                row = conn.execute("SELECT * FROM dsar_requests WHERE request_id=?", (rid,)).fetchone()
            finally:
                conn.close()
        if not row:
            return None
        try:
            payload = json.loads(row["payload_json"] or "{}")
        except Exception:
            payload = {}
        try:
            result = json.loads(row["result_json"] or "{}")
        except Exception:
            result = {}
        from jarvis.core.privacy.models import DsarRequestType, DsarStatus

        return DSARRequest(
            request_id=row["request_id"],
            user_id=row["user_id"],
            request_type=DsarRequestType(str(row["request_type"])),
            status=DsarStatus(str(row["status"])),
            created_at=str(row["created_at"] or ""),
            completed_at=row["completed_at"],
            notes=str(row["notes"] or ""),
            payload=dict(payload or {}),
            result=dict(result or {}),
            export_path=row["export_path"],
        )

    def update_dsar(self, req: DSARRequest) -> None:
        if not isinstance(req, DSARRequest):
            req = DSARRequest.model_validate(req)
        with self._lock:
            conn = self._conn()
            try:
                conn.execute(
                    "UPDATE dsar_requests SET status=?, completed_at=?, notes=?, payload_json=?, result_json=?, export_path=? WHERE request_id=?",
                    (
                        req.status.value,
                        req.completed_at,
                        req.notes,
                        json.dumps(dict(req.payload or {}), ensure_ascii=False),
                        json.dumps(dict(req.result or {}), ensure_ascii=False),
                        req.export_path,
                        req.request_id,
                    ),
                )
                conn.commit()
            finally:
                conn.close()

    # ---- processing restrictions (Art.18) ----
    def _init_processing_restrictions(self) -> None:
        # called lazily by setters to avoid bloating init; table is tiny
        with self._lock:
            conn = self._conn()
            try:
                conn.execute(
                    """
                    CREATE TABLE IF NOT EXISTS processing_restrictions (
                      user_id TEXT,
                      scope TEXT,
                      restricted INTEGER,
                      updated_at TEXT,
                      PRIMARY KEY(user_id, scope)
                    )
                    """
                )
                conn.commit()
            finally:
                conn.close()

    def set_scope_restricted(self, *, user_id: str = "default", scope: str, restricted: bool, trace_id: str = "privacy") -> bool:
        self._init_processing_restrictions()
        uid = str(user_id or "default")[:64]
        sc = str(scope or "").strip().lower()
        if not sc:
            return False
        with self._lock:
            conn = self._conn()
            try:
                conn.execute(
                    "INSERT INTO processing_restrictions(user_id, scope, restricted, updated_at) VALUES (?, ?, ?, strftime('%Y-%m-%dT%H:%M:%SZ','now')) "
                    "ON CONFLICT(user_id, scope) DO UPDATE SET restricted=excluded.restricted, updated_at=excluded.updated_at",
                    (uid, sc, 1 if restricted else 0),
                )
                conn.commit()
            finally:
                conn.close()
        # reflect common scope into prefs for visibility
        if sc == "memory" and restricted:
            _ = self._update_preferences(user_id=uid, memory_enabled=False)
        self._emit(str(trace_id or "privacy"), "privacy.processing_restriction_set", {"user_id": uid, "scope": sc, "restricted": bool(restricted)}, severity=EventSeverity.WARN)
        return True

    def is_scope_restricted(self, *, user_id: str = "default", scope: str) -> bool:
        uid = str(user_id or "default")[:64]
        sc = str(scope or "").strip().lower()
        if not sc:
            return False
        self._init_processing_restrictions()
        with self._lock:
            conn = self._conn()
            try:
                row = conn.execute("SELECT restricted FROM processing_restrictions WHERE user_id=? AND scope=?", (uid, sc)).fetchone()
            finally:
                conn.close()
        return bool(row and int(row[0] or 0) == 1)

