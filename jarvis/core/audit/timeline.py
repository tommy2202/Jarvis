from __future__ import annotations

import csv
import json
import os
import time
from typing import Any, Dict, List, Optional

from jarvis.core.audit.formatter import format_line
from jarvis.core.audit.hasher import compute_hash
from jarvis.core.audit.ingestors import (
    audit_from_core_event,
    audit_from_errors_log,
    audit_from_ops_log,
    audit_from_security_log,
    iter_jsonl_new,
)
from jarvis.core.audit.models import AuditEvent, IntegrityReport
from jarvis.core.audit.store_jsonl import AuditJsonlStore
from jarvis.core.audit.store_sqlite import AuditSqliteIndex


class AuditTimelineManager:
    def __init__(
        self,
        *,
        cfg: Dict[str, Any],
        logger=None,
        event_bus: Any = None,
        telemetry: Any = None,
        ops_logger: Any = None,
        privacy_store: Any = None,
    ):
        self.cfg = cfg or {}
        self.logger = logger
        self.event_bus = event_bus
        self.telemetry = telemetry
        self.ops = ops_logger
        self.privacy_store = privacy_store

        store = (self.cfg.get("store") or {})
        self.path_jsonl = str(store.get("path_jsonl") or os.path.join("logs", "audit", "audit_events.jsonl"))
        self.head_path = os.path.join(os.path.dirname(self.path_jsonl), "head.json")
        self.use_sqlite = bool(store.get("use_sqlite_index", True))
        self.sqlite_path = str(store.get("sqlite_path") or os.path.join("logs", "audit", "index.sqlite"))

        self._jsonl = AuditJsonlStore(path=self.path_jsonl, head_path=self.head_path)
        self._sqlite = AuditSqliteIndex(path=self.sqlite_path) if self.use_sqlite else None

        self._integrity_broken = False
        self._cursor_path = os.path.join(os.path.dirname(self.path_jsonl), "cursors.json")
        self._cursors = self._load_cursors()

        # Privacy inventory (best-effort, no content)
        if self.privacy_store is not None:
            try:
                from jarvis.core.privacy.models import DataCategory, LawfulBasis, Sensitivity
                from jarvis.core.privacy.tagging import data_record_for_file

                self.privacy_store.register_record(
                    data_record_for_file(
                        user_id="default",
                        path=self.path_jsonl,
                        category=DataCategory.AUDIT,
                        sensitivity=Sensitivity.LOW,
                        lawful_basis=LawfulBasis.LEGITIMATE_INTERESTS,
                        trace_id="startup",
                        producer="audit_timeline",
                        tags={"format": "jsonl"},
                    )
                )
                if self.use_sqlite:
                    self.privacy_store.register_record(
                        data_record_for_file(
                            user_id="default",
                            path=self.sqlite_path,
                            category=DataCategory.AUDIT,
                            sensitivity=Sensitivity.LOW,
                            lawful_basis=LawfulBasis.LEGITIMATE_INTERESTS,
                            trace_id="startup",
                            producer="audit_timeline",
                            tags={"format": "sqlite"},
                        )
                    )
            except Exception:
                pass

    # ---- wiring ----
    def start(self) -> None:
        if not bool(self.cfg.get("enabled", True)):
            return
        # subscribe to event bus (live ingestion)
        if self.event_bus is not None:
            try:
                self.event_bus.subscribe("*", self._on_event_bus, priority=200)
            except Exception:
                pass
        # verify chain + ingest logs (best effort)
        integ = self.verify_integrity(limit_last_n=int((self.cfg.get("integrity") or {}).get("verify_last_n", 2000)))
        self._integrity_broken = not bool(integ.ok)
        if bool((self.cfg.get("integrity") or {}).get("verify_on_startup", True)) and not integ.ok and self.ops is not None:
            try:
                self.ops.log(trace_id="startup", event="audit.integrity_broken", outcome="critical", details={"message": integ.message})
            except Exception:
                pass
        self.ingest_logs_once()
        self.enforce_retention()

    def stop(self) -> None:
        if self.event_bus is not None:
            try:
                self.event_bus.unsubscribe(self._on_event_bus)
            except Exception:
                pass

    # ---- ingestion ----
    def _append_event(self, ev: AuditEvent) -> Dict[str, Any]:
        payload = ev.model_dump(mode="json")
        rec = self._jsonl.append(payload)
        if self._sqlite is not None:
            try:
                rec_idx = dict(rec)
                rec_idx.pop("prev_hash", None)
                rec_idx.pop("hash", None)
                self._sqlite.upsert(rec_idx)
            except Exception:
                pass
        return rec

    def _on_event_bus(self, base_event: Any) -> None:
        ev = audit_from_core_event(base_event)
        if ev is None:
            return
        self._append_event(ev)

    def ingest_logs_once(self) -> None:
        """
        Ingest security/ops/errors logs into audit store using file offsets cursor.
        """
        # Allow tests/embedders to override source paths for determinism.
        src_cfg = (self.cfg.get("ingest_sources") or {}) if isinstance(self.cfg, dict) else {}
        sec_path = str((src_cfg.get("security") if isinstance(src_cfg, dict) else None) or os.path.join("logs", "security.jsonl"))
        ops_path = str((src_cfg.get("ops") if isinstance(src_cfg, dict) else None) or os.path.join("logs", "ops.jsonl"))
        err_path = str((src_cfg.get("errors") if isinstance(src_cfg, dict) else None) or os.path.join("logs", "errors.jsonl"))
        mapping = [
            ("security", sec_path, audit_from_security_log),
            ("ops", ops_path, audit_from_ops_log),
            ("errors", err_path, audit_from_errors_log),
        ]
        for name, path, fn in mapping:
            off = int((self._cursors.get(name) or 0))
            new_off, items = iter_jsonl_new(path, start_offset=off)
            count = 0
            for obj in items:
                ev = fn(obj)
                if ev is None:
                    continue
                self._append_event(ev)
                count += 1
            self._cursors[name] = int(new_off)
            if count and self.telemetry is not None:
                try:
                    self.telemetry.increment_counter("audit_ingested_total", count, tags={"source": name})
                except Exception:
                    pass
        self._save_cursors()

    # ---- query API ----
    def list_events(
        self,
        *,
        since: Optional[float] = None,
        until: Optional[float] = None,
        category: Optional[str] = None,
        severity_min: Optional[str] = None,
        actor_source: Optional[str] = None,
        outcome: Optional[str] = None,
        limit: int = 200,
        offset: int = 0,
    ) -> List[AuditEvent]:
        # Ensure log-derived events are up to date (cheap when no new bytes).
        try:
            self.ingest_logs_once()
        except Exception:
            pass
        limit = max(1, min(int(limit), int((self.cfg.get("export") or {}).get("max_rows", 20000))))
        offset = max(0, int(offset))
        if self._sqlite is not None:
            rows = self._sqlite.query(
                since=since,
                until=until,
                category=category,
                severity_min=severity_min,
                actor_source=actor_source,
                outcome=outcome,
                limit=limit,
                offset=offset,
            )
            return [AuditEvent.model_validate(r) for r in rows]
        # fallback: read JSONL tail and filter (limited)
        items = self._jsonl.tail(n=limit + offset + 500)
        out: List[AuditEvent] = []
        for r in reversed(items):  # oldest->newest to filter then reverse later
            try:
                ev = AuditEvent.model_validate(r)
            except Exception:
                continue
            if since is not None and ev.timestamp < float(since):
                continue
            if until is not None and ev.timestamp > float(until):
                continue
            if category and ev.category.value != str(category):
                continue
            if actor_source and ev.actor.source.value != str(actor_source):
                continue
            if outcome and ev.outcome.value != str(outcome):
                continue
            out.append(ev)
        out.sort(key=lambda e: e.timestamp, reverse=True)
        return out[offset : offset + limit]

    def get_event(self, audit_id: str) -> Optional[AuditEvent]:
        for r in self._jsonl.tail(n=5000):
            if str(r.get("audit_id")) == str(audit_id):
                try:
                    rr = dict(r)
                    rr.pop("prev_hash", None)
                    rr.pop("hash", None)
                    return AuditEvent.model_validate(rr)
                except Exception:
                    return None
        return None

    def export_json(self, path: str, *, filters: Dict[str, Any]) -> str:
        rows = self.list_events(**filters)
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump([r.model_dump() for r in rows], f, indent=2, ensure_ascii=False)
        return path

    def export_csv(self, path: str, *, filters: Dict[str, Any]) -> str:
        rows = self.list_events(**filters)
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        with open(path, "w", encoding="utf-8", newline="") as f:
            w = csv.writer(f)
            w.writerow(["timestamp", "audit_id", "trace_id", "actor_source", "category", "action", "outcome", "severity", "summary"])
            for ev in rows:
                w.writerow([ev.timestamp, ev.audit_id, ev.trace_id or "", ev.actor.source.value, ev.category.value, ev.action, ev.outcome.value, ev.severity.value, ev.summary])
        return path

    def tail_formatted(self, n: int = 20) -> List[str]:
        try:
            self.ingest_logs_once()
        except Exception:
            pass
        items = self.list_events(limit=int(n))
        return [format_line(ev) for ev in reversed(items)]

    # ---- integrity / retention ----
    def verify_integrity(self, *, limit_last_n: int = 1000) -> IntegrityReport:
        n = max(1, int(limit_last_n))
        lines = self._jsonl.tail(n=n)
        if not lines:
            return IntegrityReport(ok=True, checked=0, message="no events", head_hash=self._jsonl.read_head_hash())
        # Verify chaining within window
        checked = 0
        for idx in range(1, len(lines)):
            prev = lines[idx - 1]
            cur = lines[idx]
            prev_hash = str(cur.get("prev_hash") or "")
            if prev_hash != str(prev.get("hash") or ""):
                return IntegrityReport(ok=False, checked=checked, broken_at_line=idx, message="prev_hash mismatch", head_hash=self._jsonl.read_head_hash())
            payload = dict(cur)
            payload.pop("hash", None)
            payload.pop("prev_hash", None)
            h = compute_hash(str(cur.get("prev_hash") or ""), payload)
            if h != str(cur.get("hash") or ""):
                return IntegrityReport(ok=False, checked=checked, broken_at_line=idx, message="hash mismatch", head_hash=self._jsonl.read_head_hash())
            checked += 1
        return IntegrityReport(ok=True, checked=checked, message="ok", head_hash=self._jsonl.read_head_hash())

    def enforce_retention(self) -> None:
        ret = self.cfg.get("retention") or {}
        days = int(ret.get("days", 90))
        max_events = int(ret.get("max_events", 50000))
        cutoff = time.time() - float(days * 86400)
        # sqlite pruning is cheap; jsonl compaction happens only on purge
        if self._sqlite is not None:
            try:
                self._sqlite.delete_older_than(cutoff)
            except Exception:
                pass
            try:
                # cap max events by deleting oldest beyond cap (simple)
                # (skip: requires extra queries; purge handles deep cleanup)
                pass
            except Exception:
                pass

    def purge_and_compact(self) -> Dict[str, Any]:
        """
        Admin operation: enforce retention by rewriting JSONL and rebuilding sqlite.
        Rechains hashes deterministically.
        """
        ret = self.cfg.get("retention") or {}
        days = int(ret.get("days", 90))
        max_events = int(ret.get("max_events", 50000))
        cutoff = time.time() - float(days * 86400)

        # Read from sqlite if available; otherwise read jsonl.
        if self._sqlite is not None:
            rows = self._sqlite.query(since=cutoff, limit=max_events, offset=0)
            # rows are newest-first; keep oldest-first for rechaining
            rows.sort(key=lambda r: float(r.get("timestamp") or 0.0))
        else:
            rows = []
            for r in self._jsonl.iter_lines():
                try:
                    ts = float(r.get("timestamp") or 0.0)
                except Exception:
                    continue
                if ts < cutoff:
                    continue
                rows.append(r)
            rows.sort(key=lambda r: float(r.get("timestamp") or 0.0))
            if len(rows) > max_events:
                rows = rows[-max_events:]

        tmp = self.path_jsonl + ".tmp"
        head = "0" * 64
        written = 0
        os.makedirs(os.path.dirname(self.path_jsonl), exist_ok=True)
        with open(tmp, "w", encoding="utf-8") as f:
            for r in rows:
                # strip existing chain fields
                payload = dict(r)
                payload.pop("hash", None)
                payload.pop("prev_hash", None)
                rec = {"prev_hash": head, **payload}
                rec_hash = compute_hash(head, payload)
                rec["hash"] = rec_hash
                head = rec_hash
                f.write(json.dumps(rec, ensure_ascii=False) + "\n")
                written += 1
        os.replace(tmp, self.path_jsonl)
        self._jsonl.write_head_hash(head)
        if self._sqlite is not None:
            self._sqlite.drop_all()
            for r in self._jsonl.iter_lines():
                try:
                    rr = dict(r)
                    rr.pop("prev_hash", None)
                    rr.pop("hash", None)
                    self._sqlite.upsert(rr)
                except Exception:
                    continue
        return {"written": written, "head_hash": head}

    def integrity_broken(self) -> bool:
        return bool(self._integrity_broken)

    # ---- cursor persistence ----
    def _load_cursors(self) -> Dict[str, int]:
        try:
            with open(self._cursor_path, "r", encoding="utf-8") as f:
                obj = json.load(f)
            if isinstance(obj, dict):
                return {k: int(v) for k, v in obj.items()}
        except Exception:
            pass
        return {}

    def _save_cursors(self) -> None:
        try:
            tmp = self._cursor_path + ".tmp"
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(self._cursors, f, indent=2, ensure_ascii=False)
                f.write("\n")
            os.replace(tmp, self._cursor_path)
        except Exception:
            pass

