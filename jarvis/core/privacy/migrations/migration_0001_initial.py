from __future__ import annotations

import time
from typing import Any


def migrate(conn: Any) -> None:
    """
    Initial privacy schema metadata.
    Idempotent and transactional (caller controls commit/rollback).
    """
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS privacy_meta (
          key TEXT PRIMARY KEY,
          value TEXT,
          updated_at TEXT
        )
        """
    )
    conn.execute(
        "INSERT OR REPLACE INTO privacy_meta (key, value, updated_at) VALUES (?, ?, ?)",
        ("schema_version", "1", _now_iso()),
    )


def _now_iso() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
