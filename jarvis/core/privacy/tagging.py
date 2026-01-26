from __future__ import annotations

"""
Tagging helpers for privacy-safe data inventory.

Design goal:
Create DataRecord envelopes for persistent artifacts *without* including raw content.
"""

import hashlib
from typing import Dict, Optional

from jarvis.core.privacy.models import DataCategory, DataRecord, LawfulBasis, Sensitivity, StorageKind


def _hash_ref(storage_ref: str) -> str:
    s = str(storage_ref or "").encode("utf-8", errors="ignore")
    return hashlib.sha256(s).hexdigest()


def data_record_for_file(
    *,
    user_id: str = "default",
    path: str,
    category: DataCategory,
    sensitivity: Sensitivity = Sensitivity.LOW,
    lawful_basis: LawfulBasis = LawfulBasis.LEGITIMATE_INTERESTS,
    trace_id: Optional[str] = None,
    producer: str = "core",
    tags: Optional[Dict[str, str]] = None,
    size_bytes: int | None = None,
) -> DataRecord:
    """
    Create a DataRecord for a file-based artifact (logs/json/sqlite/etc).

    NOTE: This intentionally does NOT include any file contents.
    """
    rec = DataRecord(
        user_id=str(user_id or "default"),
        data_category=category,
        sensitivity=sensitivity,
        lawful_basis=lawful_basis,
        storage_kind=StorageKind.FILE,
        storage_ref=str(path).replace("\\", "/"),
        storage_ref_hash=_hash_ref(str(path)),
        trace_id=(str(trace_id) if trace_id else None),
        producer=str(producer or "core"),
        tags=tags or {},
        size_bytes=size_bytes,
        content_present=False,
    )
    return rec


def data_record_for_sqlite(
    *,
    user_id: str = "default",
    db_path: str,
    table: str,
    category: DataCategory,
    sensitivity: Sensitivity = Sensitivity.LOW,
    lawful_basis: LawfulBasis = LawfulBasis.LEGITIMATE_INTERESTS,
    trace_id: Optional[str] = None,
    producer: str = "core",
    tags: Optional[Dict[str, str]] = None,
) -> DataRecord:
    normalized_path = str(db_path).replace("\\", "/")
    storage_ref = f"{normalized_path}#{table}"
    rec = DataRecord(
        user_id=str(user_id or "default"),
        data_category=category,
        sensitivity=sensitivity,
        lawful_basis=lawful_basis,
        storage_kind=StorageKind.SQLITE,
        storage_ref=storage_ref,
        storage_ref_hash=_hash_ref(storage_ref),
        trace_id=(str(trace_id) if trace_id else None),
        producer=str(producer or "core"),
        tags=tags or {},
        content_present=False,
    )
    return rec

