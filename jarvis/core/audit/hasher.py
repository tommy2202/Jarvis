from __future__ import annotations

import hashlib
import json
from typing import Any, Dict, Optional, Tuple


def canonical_json(obj: Dict[str, Any]) -> str:
    # Deterministic JSON (no whitespace, sorted keys)
    return json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def compute_hash(prev_hash: str, payload: Dict[str, Any]) -> str:
    h = hashlib.sha256()
    h.update(prev_hash.encode("utf-8"))
    h.update(b"\n")
    h.update(canonical_json(payload).encode("utf-8"))
    return h.hexdigest()


def chain_record(*, payload: Dict[str, Any], prev_hash: str) -> Dict[str, Any]:
    rec = dict(payload)
    rec["prev_hash"] = prev_hash
    rec["hash"] = compute_hash(prev_hash, payload)
    return rec

