from __future__ import annotations

"""
Redaction helpers for module audit payloads.

WHY THIS FILE EXISTS:
Audit payloads must never include secrets or raw file contents. This module
provides strict allowlisted shaping for module lifecycle events.
"""

from typing import Any, Dict


def redact_module_payload(payload: Dict[str, Any]) -> Dict[str, Any]:
    """
    Keep only safe, non-sensitive fields.
    """
    p = payload or {}
    allow = {
        "module_id",
        "module_path",
        "fingerprint",
        "contract_hash",
        "installed",
        "enabled",
        "requires_admin_to_enable",
        "safe_auto_enabled",
        "missing_on_disk",
        "pending_user_input",
        "changed_requires_review",
        "reason",
        "action",
        "intent_id",
    }
    out: Dict[str, Any] = {}
    for k in allow:
        if k in p:
            out[k] = p.get(k)
    # Never include manifest raw contents, file lists, or arbitrary user text.
    return out

