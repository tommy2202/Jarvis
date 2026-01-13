from __future__ import annotations

"""
Fingerprint utilities for module discovery.

WHY THIS FILE EXISTS:
Discovery must be able to detect module changes without importing/executing
module code. Fingerprints are derived from manifest text + file metadata.
"""

import hashlib
import json
import os
from typing import Any, Dict, Iterable, Tuple


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def fingerprint_module(*, module_dir: str, manifest_bytes: bytes | None, file_entries: Iterable[Tuple[str, int]]) -> str:
    """
    Compute a deterministic fingerprint:
    - manifest bytes (if present) are hashed directly
    - file_entries is an iterable of (relative_path, mtime_int)

    We intentionally do NOT read file contents besides module.json.
    """
    man_hash = sha256_hex(manifest_bytes or b"")
    files = [{"path": p, "mtime": int(m)} for (p, m) in sorted(file_entries, key=lambda x: x[0])]
    payload = {"manifest_sha256": man_hash, "files": files}
    blob = json.dumps(payload, ensure_ascii=False, sort_keys=True).encode("utf-8")
    return sha256_hex(blob)


def list_files_for_fingerprint(module_dir: str) -> list[tuple[str, int]]:
    """
    Return (relative_path, mtime_int) for all files under module_dir excluding
    __pycache__ and hidden directories.
    """
    out: list[tuple[str, int]] = []
    for root, dirs, files in os.walk(module_dir):
        dirs[:] = [d for d in dirs if d != "__pycache__" and not d.startswith(".")]
        for fn in files:
            if fn.endswith(".pyc") or fn.endswith(".pyo"):
                continue
            rel = os.path.relpath(os.path.join(root, fn), module_dir)
            try:
                st = os.stat(os.path.join(root, fn))
                out.append((rel.replace("\\", "/"), int(st.st_mtime)))
            except Exception:
                out.append((rel.replace("\\", "/"), 0))
    return out


def contract_hash_from_manifest_dict(manifest: Dict[str, Any]) -> str:
    """
    Hash only contract-relevant fields. Cosmetic changes should not require review.
    """
    intents = []
    for it in (manifest.get("intents") or []):
        if not isinstance(it, dict):
            continue
        intents.append(
            {
                "intent_id": str(it.get("intent_id") or ""),
                "required_capabilities": sorted([str(x) for x in (it.get("required_capabilities") or []) if str(x)]),
                "resource_class": str(it.get("resource_class") or ""),
                "execution_mode": str(it.get("execution_mode") or ""),
            }
        )
    payload = {
        "schema_version": int(manifest.get("schema_version") or 1),
        "module_id": str(manifest.get("module_id") or ""),
        "entrypoint": str(manifest.get("entrypoint") or ""),
        "intents": sorted(intents, key=lambda x: x["intent_id"]),
    }
    blob = json.dumps(payload, ensure_ascii=False, sort_keys=True).encode("utf-8")
    return sha256_hex(blob)

