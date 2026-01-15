from __future__ import annotations

"""
Privacy gates: separate "can perform action" from "can persist data".

Enforcement rules:
- Capability/policy engines remain authoritative for allow/deny execution.
- Privacy gates only control persistence behavior (ephemeral mode vs persisted).

This module is the single core path for persistence gating.
"""

import contextlib
import contextvars
from typing import Any, Dict, List


_PERSIST_ALLOWED: contextvars.ContextVar[bool] = contextvars.ContextVar("jarvis.persist_allowed", default=True)


def persist_allowed_current() -> bool:
    return bool(_PERSIST_ALLOWED.get())


@contextlib.contextmanager
def persistence_context(*, persist_allowed: bool):
    tok = _PERSIST_ALLOWED.set(bool(persist_allowed))
    try:
        yield
    finally:
        try:
            _PERSIST_ALLOWED.reset(tok)
        except Exception:
            pass


class PrivacyGate:
    def __init__(self, *, privacy_store: Any):
        self.privacy_store = privacy_store

    def evaluate(self, context: Dict[str, Any], intent_meta: Dict[str, Any]) -> bool:
        """
        Returns persist_allowed boolean.

        Rules:
        - If any required privacy scope lacks consent or is restricted -> persist_allowed=False
        - If context explicitly requests ephemeral -> persist_allowed=False
        """
        ctx = context or {}
        if bool(ctx.get("ephemeral", False)):
            return False
        scopes: List[str] = []
        if isinstance(ctx.get("privacy_scopes"), list):
            scopes.extend([str(x).lower() for x in ctx.get("privacy_scopes") if str(x)])
        if isinstance((intent_meta or {}).get("privacy_scopes"), list):
            scopes.extend([str(x).lower() for x in (intent_meta or {}).get("privacy_scopes") if str(x)])
        scopes = sorted(set([s for s in scopes if s]))
        if not scopes:
            # No personal-data persistence tagged => allow metadata persistence only.
            return True
        user_id = str(ctx.get("user_id") or "default")
        for sc in scopes:
            try:
                if bool(getattr(self.privacy_store, "is_scope_restricted")(user_id=user_id, scope=sc)):
                    return False
            except Exception:
                # Fail-safe: do not allow persistence if restriction status cannot be checked
                return False
            try:
                c = getattr(self.privacy_store, "get_consent")(user_id=user_id, scope=sc)
                if not (c and bool(getattr(c, "granted", False))):
                    return False
            except Exception:
                return False
        return True

