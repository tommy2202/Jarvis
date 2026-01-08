from __future__ import annotations

import json
import os
import sqlite3
from typing import Any, Dict, List, Optional, Tuple


class AuditSqliteIndex:
    def __init__(self, *, path: str):
        self.path = path
        os.makedirs(os.path.dirname(path), exist_ok=True)
        self._init()

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path)
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA synchronous=NORMAL;")
        return conn

    def _init(self) -> None:
        with self._conn() as c:
            c.execute(
                """
                CREATE TABLE IF NOT EXISTS audit_events (
                  audit_id TEXT PRIMARY KEY,
                  ts REAL NOT NULL,
                  trace_id TEXT,
                  actor_source TEXT,
                  category TEXT,
                  action TEXT,
                  outcome TEXT,
                  severity TEXT,
                  summary TEXT,
                  json TEXT NOT NULL
                )
                """
            )
            c.execute("CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_events(ts);")
            c.execute("CREATE INDEX IF NOT EXISTS idx_audit_cat ON audit_events(category, ts);")
            c.execute("CREATE INDEX IF NOT EXISTS idx_audit_act ON audit_events(action, ts);")

    def upsert(self, event: Dict[str, Any]) -> None:
        with self._conn() as c:
            c.execute(
                """
                INSERT OR REPLACE INTO audit_events(audit_id, ts, trace_id, actor_source, category, action, outcome, severity, summary, json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    str(event.get("audit_id")),
                    float(event.get("timestamp") or 0.0),
                    event.get("trace_id"),
                    ((event.get("actor") or {}).get("source") if isinstance(event.get("actor"), dict) else None),
                    str(event.get("category") or ""),
                    str(event.get("action") or ""),
                    str(event.get("outcome") or ""),
                    str(event.get("severity") or ""),
                    str(event.get("summary") or ""),
                    json.dumps(event, ensure_ascii=False),
                ),
            )

    def query(
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
    ) -> List[Dict[str, Any]]:
        where = []
        params: list[Any] = []
        if since is not None:
            where.append("ts >= ?")
            params.append(float(since))
        if until is not None:
            where.append("ts <= ?")
            params.append(float(until))
        if category:
            where.append("category = ?")
            params.append(str(category))
        if actor_source:
            where.append("actor_source = ?")
            params.append(str(actor_source))
        if outcome:
            where.append("outcome = ?")
            params.append(str(outcome))
        # severity_min is best-effort ordering INFO<WARN<ERROR<CRITICAL
        if severity_min:
            order = {"INFO": 0, "WARN": 1, "ERROR": 2, "CRITICAL": 3}
            minv = order.get(str(severity_min).upper(), 0)
            where.append("(CASE severity WHEN 'INFO' THEN 0 WHEN 'WARN' THEN 1 WHEN 'ERROR' THEN 2 WHEN 'CRITICAL' THEN 3 ELSE 0 END) >= ?")
            params.append(int(minv))

        sql = "SELECT json FROM audit_events"
        if where:
            sql += " WHERE " + " AND ".join(where)
        sql += " ORDER BY ts DESC LIMIT ? OFFSET ?"
        params.append(int(limit))
        params.append(int(offset))
        out: List[Dict[str, Any]] = []
        with self._conn() as c:
            for (blob,) in c.execute(sql, params):
                try:
                    out.append(json.loads(blob))
                except Exception:
                    continue
        return out

    def delete_older_than(self, cutoff_ts: float) -> int:
        with self._conn() as c:
            cur = c.execute("DELETE FROM audit_events WHERE ts < ?", (float(cutoff_ts),))
            return int(cur.rowcount or 0)

    def count(self) -> int:
        with self._conn() as c:
            row = c.execute("SELECT COUNT(1) FROM audit_events").fetchone()
            return int(row[0] if row else 0)

    def drop_all(self) -> None:
        with self._conn() as c:
            c.execute("DELETE FROM audit_events;")

