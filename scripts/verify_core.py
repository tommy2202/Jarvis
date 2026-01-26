"""
Core smoke verification script.

WHY THIS FILE EXISTS:
This repo needs a deterministic, offline "smoke test" that validates the core
security/enforcement plumbing without requiring a secure store key or admin
unlock. It is intentionally small and safe to run repeatedly.

Usage:
  python scripts/verify_core.py
"""

from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path


class _Logger:
    def info(self, *_a, **_k): ...
    def warning(self, *_a, **_k): ...
    def error(self, *_a, **_k): ...


def _repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def main() -> int:
    try:
        os.chdir(_repo_root())

        # ---- Load config system (read-only, deterministic) ----
        from jarvis.core.config.manager import ConfigManager

        cfg_mgr = ConfigManager(logger=_Logger(), read_only=True)
        cfg_mgr.load_all()
        cfg_obj = cfg_mgr.get()

        # ---- Instantiate CapabilityEngine + PolicyEngine ----
        from jarvis.core.capabilities.audit import CapabilityAuditLogger
        from jarvis.core.capabilities.engine import CapabilityEngine
        from jarvis.core.capabilities.loader import validate_and_normalize
        from jarvis.core.capabilities.models import RequestContext, RequestSource
        from jarvis.core.policy.engine import PolicyEngine
        from jarvis.core.policy.loader import load_policy_config

        cap_raw = cfg_mgr.read_non_sensitive("capabilities.json")
        cap_cfg = validate_and_normalize(cap_raw)

        pol_cfg, pol_failsafe, pol_err = load_policy_config(cfg_mgr)
        pol_engine = PolicyEngine(cfg=pol_cfg, failsafe=pol_failsafe, fail_message=pol_err)

        with tempfile.TemporaryDirectory() as td:
            audit_path = Path(td) / "security_audit.jsonl"
            cap_engine = CapabilityEngine(cfg=cap_cfg, audit=CapabilityAuditLogger(path=str(audit_path)), logger=None)

            # ---- Evaluate one ALLOW ----
            allow_ctx = RequestContext(
                trace_id="verify",
                source=RequestSource.cli,
                intent_id="music.play",
                is_admin=False,
                secure_store_mode="KEY_MISSING",
            )
            allow_dec = cap_engine.evaluate(allow_ctx)
            assert allow_dec.allowed is True, "Expected allow decision for music.play"

            # ---- Evaluate one DENY (unknown intent) ----
            deny_ctx = RequestContext(
                trace_id="verify",
                source=RequestSource.cli,
                intent_id="unknown.intent",
                is_admin=False,
                secure_store_mode="KEY_MISSING",
            )
            deny_dec = cap_engine.evaluate(deny_ctx)
            assert deny_dec.allowed is False, "Expected deny decision for unknown intent"

            # Confirm audit logging can append without error (deny path forces audit).
            assert audit_path.exists() and audit_path.stat().st_size > 0, "Expected audit log to be written"

            # ---- Invoke dispatcher on a safe intent and ensure it executes ----
            from jarvis.core.dispatcher import Dispatcher
            from jarvis.core.events import EventLogger
            from jarvis.core.module_registry import ModuleRegistry
            from jarvis.core.security import AdminSession, PermissionPolicy, SecurityManager
            from jarvis.core.secure_store import SecureStore

            # No USB key required: point to a missing file to simulate KEY_MISSING.
            store = SecureStore(usb_key_path=str(Path(td) / "usb_missing.bin"), store_path=str(Path(td) / "store.enc"))
            security = SecurityManager(secure_store=store, admin_session=AdminSession(timeout_seconds=60))

            reg = ModuleRegistry()
            reg.register("jarvis.modules.music")

            dispatcher = Dispatcher(
                registry=reg,
                policy=PermissionPolicy(intents={}),
                security=security,
                event_logger=EventLogger(str(Path(td) / "events.jsonl")),
                logger=_Logger(),
                capability_engine=cap_engine,
                policy_engine=pol_engine,
                secure_store=store,
                inline_intent_allowlist=["music.play"],
                execution_config=cfg_obj.execution.model_dump(),
            )

            res = dispatcher.dispatch(
                "verify",
                "music.play",
                "music",
                {"song": "x", "service": "y"},
                {"source": "cli", "client": {"id": "verify"}},
            )
            assert res.ok is True, "Expected dispatcher execution for safe intent"

        return 0
    except AssertionError:
        return 2
    except Exception:
        return 3


if __name__ == "__main__":
    sys.exit(main())

