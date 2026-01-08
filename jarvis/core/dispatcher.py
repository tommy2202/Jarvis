from __future__ import annotations

from dataclasses import dataclass
import json
import importlib
import multiprocessing as mp
import queue
import threading
from typing import Any, Dict, Optional, Tuple

from jarvis.core.events import EventLogger
from jarvis.core.events import redact
from jarvis.core.module_registry import ModuleRegistry
from jarvis.core.security import PermissionPolicy, SecurityManager
from jarvis.core.error_reporter import ErrorReporter
from jarvis.core.errors import AdminRequiredError, JarvisError, PermissionDeniedError
from jarvis.core.capabilities.models import RequestContext, RequestSource
from jarvis.core.events.models import BaseEvent, EventSeverity, SourceSubsystem


def _invoke_module_handle_in_subprocess(q_out, module_path: str, intent_id: str, args: Dict[str, Any], context: Dict[str, Any]) -> None:  # noqa: ANN001
    """
    Subprocess entrypoint for execution_mode='process'.
    Must be top-level for multiprocessing spawn (Windows-compatible).
    """
    try:
        mod = importlib.import_module(str(module_path))
        handler = getattr(mod, "handle", None)
        if not callable(handler):
            q_out.put({"ok": False, "err": "module_missing_handle"})
            return
        res = handler(intent_id=intent_id, args=args, context=context)
        q_out.put({"ok": True, "res": res})
    except Exception as e:  # noqa: BLE001
        try:
            q_out.put({"ok": False, "err": str(e)})
        except Exception:
            pass


@dataclass(frozen=True)
class DispatchResult:
    ok: bool
    reply: str
    module_output: Optional[Dict[str, Any]] = None
    denied_reason: Optional[str] = None
    require_confirmation: bool = False
    modifications: Optional[Dict[str, Any]] = None
    pending_confirmation: Optional[Dict[str, Any]] = None


class Dispatcher:
    """
    Single enforcement point:
    - only executes intents known in registry/config
    - enforces permissions/admin gating
    - enforces resource_intensive => admin-only
    - never executes arbitrary shell
    """

    def __init__(
        self,
        registry: ModuleRegistry,
        policy: PermissionPolicy,
        security: SecurityManager,
        event_logger: EventLogger,
        logger,
        error_reporter: ErrorReporter | None = None,
        telemetry: Any = None,
        capability_engine: Any = None,
        breaker_registry: Any = None,
        secure_store: Any = None,
        event_bus: Any = None,
    ):
        self.registry = registry
        self.policy = policy
        self.security = security
        self.event_logger = event_logger
        self.logger = logger
        self.error_reporter = error_reporter or ErrorReporter()
        self.telemetry = telemetry
        self.capability_engine = capability_engine
        self.breaker_registry = breaker_registry
        self.secure_store = secure_store
        self.event_bus = event_bus

    def _enforce(self, trace_id: str, intent_id: str) -> Tuple[bool, str]:
        perms = self.policy.for_intent(intent_id)
        requires_admin = bool(perms.get("requires_admin", False))
        resource_intensive = bool(perms.get("resource_intensive", False))
        network_access = bool(perms.get("network_access", False))

        # Fail-safe: resource-intensive intents are admin-only
        if resource_intensive:
            requires_admin = True
        # Fail-safe: intents requiring network are admin-only (offline-first default).
        if network_access:
            requires_admin = True

        if requires_admin and not self.security.is_admin():
            return False, "admin required"
        return True, "ok"

    @staticmethod
    def _is_core_intent(intent_id: str, mod_meta: Dict[str, Any]) -> bool:
        # Core intents are handled in JarvisApp and must not require module contracts.
        if str(intent_id or "").startswith("core."):
            return True
        # Explicit module-level override (rare, but supported for back-compat).
        return bool((mod_meta or {}).get("core", False))

    @staticmethod
    def _jsonable_dict(x: Any) -> Dict[str, Any]:
        """
        Best-effort: ensure process-execution context is JSON-serializable.
        We never send secrets; context should already be redacted by callers.
        """
        if not isinstance(x, dict):
            return {}
        try:
            json.dumps(x, ensure_ascii=False)
            return dict(x)
        except Exception:
            # Redact returns primitives; fall back to that.
            try:
                rx = redact(x)
                if isinstance(rx, dict):
                    json.dumps(rx, ensure_ascii=False)
                    return dict(rx)
            except Exception:
                pass
        return {}

    @staticmethod
    def _validate_module_contract(
        *,
        intent_id: str,
        mod_meta: Dict[str, Any],
        mapped_caps: list[str],
    ) -> Tuple[bool, str]:
        """
        Non-core intents must have deterministic contract metadata so enforcement can't drift:
        - execution_mode: inline|thread|process
        - resource_class: non-empty string
        - required capabilities declaration that matches capabilities.json mapping
        """
        meta = mod_meta or {}
        execution_mode = str(meta.get("execution_mode") or "").strip().lower()
        resource_class = str(meta.get("resource_class") or "").strip()

        # Resolve declared capabilities for this intent.
        declared: list[str] = []
        by_intent = meta.get("capabilities_by_intent")
        if isinstance(by_intent, dict):
            raw = by_intent.get(intent_id)
            if isinstance(raw, list):
                declared = [str(x) for x in raw if str(x)]
        if not declared:
            raw = meta.get("required_capabilities")
            if isinstance(raw, list):
                declared = [str(x) for x in raw if str(x)]

        if not execution_mode or execution_mode not in {"inline", "thread", "process"}:
            return False, "missing/invalid execution_mode"
        if not resource_class:
            return False, "missing resource_class"
        if declared is None or not isinstance(declared, list):
            return False, "missing required capabilities"

        # Capabilities mapping is authoritative; contract must match to prevent drift.
        if set(declared) != set(mapped_caps):
            return False, "capabilities mismatch"

        return True, "ok"

    @staticmethod
    def _execute_handler(
        *,
        execution_mode: str,
        handler,
        module_path: str,
        intent_id: str,
        args: Dict[str, Any],
        context: Dict[str, Any],
    ) -> Dict[str, Any]:
        mode = str(execution_mode or "inline").lower()
        if mode == "inline":
            return handler(intent_id=intent_id, args=args, context=context)

        if mode == "thread":
            out: Dict[str, Any] = {}
            err: Dict[str, Any] = {}

            def run() -> None:
                try:
                    nonlocal out
                    out = handler(intent_id=intent_id, args=args, context=context)
                except Exception as e:  # noqa: BLE001
                    err["e"] = e

            t = threading.Thread(target=run, name=f"dispatch:{intent_id}", daemon=True)
            t.start()
            t.join(timeout=30.0)
            if t.is_alive():
                raise TimeoutError("handler thread timed out")
            if "e" in err:
                raise err["e"]
            return out

        if mode == "process":
            # Spawn a fresh process (Windows-compatible). Requires JSON-safe args/context.
            # IMPORTANT: target must be a top-level callable under spawn, so we import by module_path.
            ctx_mp = mp.get_context("spawn")
            q = ctx_mp.Queue()  # type: ignore[attr-defined]
            p = ctx_mp.Process(target=_invoke_module_handle_in_subprocess, args=(q, module_path, intent_id, args, context), daemon=True)
            p.start()
            p.join(timeout=30.0)
            if p.is_alive():
                try:
                    p.terminate()
                except Exception:
                    pass
                raise TimeoutError("handler process timed out")
            try:
                msg = q.get_nowait()
            except Exception:
                msg = {"ok": False, "err": "no_result"}
            if not msg.get("ok"):
                raise RuntimeError(str(msg.get("err") or "handler failed"))
            return msg.get("res") or {}

        raise ValueError("unknown execution_mode")

    def dispatch(self, trace_id: str, intent_id: str, module_id: str, args: Dict[str, Any], context: Dict[str, Any]) -> DispatchResult:
        mod = self.registry.get_by_id(module_id)
        if not mod:
            self.event_logger.log(trace_id, "dispatch.refused", {"reason": "unknown module_id", "module_id": module_id})
            if self.telemetry is not None:
                try:
                    self.telemetry.increment_counter("errors_total", 1, tags={"subsystem": "dispatcher", "severity": "WARN"})
                except Exception:
                    pass
            return DispatchResult(ok=False, reply="I can’t execute that module.", denied_reason="unknown module")

        # Dispatcher is the single, authoritative enforcement point:
        # - deny-by-default for unmapped intents
        # - capability engine hard gate (required)
        # - policy engine may only further restrict, never grant
        if self.capability_engine is None:
            self.event_logger.log(trace_id, "dispatch.refused", {"reason": "capability_engine_missing", "intent_id": intent_id, "module_id": module_id})
            return DispatchResult(ok=False, reply="I can’t execute actions right now.", denied_reason="capability_engine_missing")

        # Strict intent mapping: intent_id must be registered in capabilities policy.
        intent_reqs = {}
        try:
            intent_reqs = getattr(self.capability_engine, "cfg", None).intent_requirements or {}
        except Exception:
            intent_reqs = {}
        if intent_id not in intent_reqs:
            remediation = "Intent is not registered in capabilities policy. Add it to config/capabilities.json intent_requirements."
            self.event_logger.log(trace_id, "dispatch.refused", {"reason": "intent_unmapped", "intent_id": intent_id, "module_id": module_id})
            if self.event_bus is not None:
                try:
                    self.event_bus.publish_nowait(
                        BaseEvent(
                            event_type="intent.denied",
                            trace_id=trace_id,
                            source_subsystem=SourceSubsystem.dispatcher,
                            severity=EventSeverity.WARN,
                            payload={"intent_id": intent_id, "reasons": ["intent_unmapped"], "remediation": remediation},
                        )
                    )
                except Exception:
                    pass
            return DispatchResult(ok=False, reply=remediation, denied_reason="intent_unmapped")

        # Contract enforcement (non-core intents): deny if incomplete to prevent drift/bypass.
        mapped_caps = list(intent_reqs.get(intent_id) or [])
        if not self._is_core_intent(intent_id, mod.meta):
            ok, why = self._validate_module_contract(intent_id=intent_id, mod_meta=mod.meta or {}, mapped_caps=mapped_caps)
            if not ok:
                remediation = "Module contract incomplete. Run /modules wizard or update module manifest."
                self.event_logger.log(trace_id, "dispatch.refused", {"reason": "contract_invalid", "intent_id": intent_id, "module_id": module_id, "detail": why})
                if self.event_bus is not None:
                    try:
                        self.event_bus.publish_nowait(
                            BaseEvent(
                                event_type="intent.denied",
                                trace_id=trace_id,
                                source_subsystem=SourceSubsystem.dispatcher,
                                severity=EventSeverity.WARN,
                                payload={"intent_id": intent_id, "reasons": ["contract_invalid", why], "remediation": remediation},
                            )
                        )
                    except Exception:
                        pass
                return DispatchResult(ok=False, reply=remediation, denied_reason="contract_invalid")

        client = (context or {}).get("client") or {}
        source_s = str((context or {}).get("source") or (context or {}).get("request_source") or client.get("source") or client.get("name") or "cli").lower()
        if source_s not in {"voice", "cli", "web", "ui", "system"}:
            source_s = "cli"
        shutting_down = bool((context or {}).get("shutting_down", False))
        safe_mode = bool((context or {}).get("safe_mode", False))
        client_id = str(client.get("id") or client.get("client_id") or "")

        breaker_status = {}
        try:
            if self.breaker_registry is not None:
                breaker_status = {"breakers": self.breaker_registry.status()}
        except Exception:
            breaker_status = {}

        secure_mode = None
        try:
            if self.secure_store is not None:
                st = self.secure_store.status()
                secure_mode = str(getattr(st, "mode").value if hasattr(getattr(st, "mode"), "value") else getattr(st, "mode"))
        except Exception:
            secure_mode = None

        ctx = RequestContext(
            trace_id=trace_id,
            source=RequestSource(source_s),
            client_id=client_id or None,
            is_admin=bool(self.security.is_admin()),
            safe_mode=safe_mode,
            shutting_down=shutting_down,
            subsystem_health=breaker_status,
            intent_id=intent_id,
            # Legacy flags are non-authoritative; keep conservative defaults.
            resource_intensive=bool(mod.meta.get("resource_intensive", False)),
            network_requested=False,
            secure_store_mode=secure_mode,
            confirmed=bool((context or {}).get("confirmed", False)),
        )

        # Capability hard gate first (no policy here; dispatcher applies policy separately as restrict-only).
        dec = self.capability_engine.evaluate(ctx, run_policy=False)
        self.event_logger.log(trace_id, "dispatch.capabilities", {"allowed": dec.allowed, "required": dec.required_capabilities, "denied": dec.denied_capabilities, "reasons": dec.reasons})
        if not dec.allowed:
            if self.event_bus is not None:
                try:
                    self.event_bus.publish_nowait(
                        BaseEvent(
                            event_type="intent.denied",
                            trace_id=trace_id,
                            source_subsystem=SourceSubsystem.dispatcher,
                            severity=EventSeverity.WARN,
                            payload={"intent_id": intent_id, "denied_caps": dec.denied_capabilities, "reasons": dec.reasons},
                        )
                    )
                except Exception:
                    pass
            msg = "I can’t do that right now."
            if any("admin" in r.lower() for r in (dec.reasons or [])) or str(dec.remediation or "").lower().startswith("unlock admin"):
                msg = AdminRequiredError().user_message
            elif dec.remediation:
                msg = str(dec.remediation)[:200]
            self.error_reporter.write_error(
                JarvisError(code="permission_denied", user_message=msg, context={"intent_id": intent_id, "denied_caps": dec.denied_capabilities}),
                trace_id=trace_id,
                subsystem="dispatcher",
                internal_exc=None,
            )
            return DispatchResult(ok=False, reply=msg, denied_reason="capability_denied")

        # Policy engine is applied after capabilities and may only further restrict.
        pol = getattr(self.capability_engine, "policy_engine", None)
        policy_mods: Dict[str, Any] = {}
        if pol is not None:
            try:
                from jarvis.core.policy.models import PolicyContext

                rc = None
                try:
                    rg = getattr(self.capability_engine, "resource_governor", None)
                    if rg is not None:
                        rc = bool(rg.is_over_budget())
                except Exception:
                    rc = None
                pctx = PolicyContext(
                    trace_id=trace_id,
                    intent_id=intent_id,
                    required_capabilities=list(dec.required_capabilities or []),
                    source=source_s,
                    client_id=client_id or None,
                    client_ip=None,
                    is_admin=bool(ctx.is_admin),
                    safe_mode=bool(ctx.safe_mode),
                    shutting_down=bool(ctx.shutting_down),
                    secure_store_mode=secure_mode,
                    tags=[("resource_intensive" if ctx.resource_intensive else ""), ("networked" if ctx.network_requested else "")],
                    resource_over_budget=rc,
                    confirmed=bool(getattr(ctx, "confirmed", False)),
                )
                pctx.tags = [t for t in (pctx.tags or []) if t]
                pdec = pol.evaluate(pctx)
                if not bool(pdec.allowed):
                    # Policy confirmation flow: do not execute; return pending action.
                    if bool(getattr(pdec, "require_confirmation", False)):
                        return DispatchResult(
                            ok=False,
                            reply=str(pdec.remediation or "Confirmation required. Reply 'confirm' to proceed or 'cancel' to abort."),
                            denied_reason="confirmation_required",
                            require_confirmation=True,
                            modifications=dict(getattr(pdec, "modifications", {}) or {}),
                            pending_confirmation={
                                "intent_id": intent_id,
                                "module_id": module_id,
                                "args": redact(args or {}),
                                "context": redact(context or {}),
                                "expires_seconds": 15,
                            },
                        )
                    msg = str(pdec.remediation or "Denied by policy.")[:200]
                    if any("admin" in str(pdec.final_reason or "").lower() for _ in [0]) and not bool(ctx.is_admin):
                        msg = AdminRequiredError().user_message
                    self.error_reporter.write_error(
                        JarvisError(code="permission_denied", user_message=msg, context={"intent_id": intent_id, "policy_reason": str(pdec.final_reason or "")}),
                        trace_id=trace_id,
                        subsystem="dispatcher",
                        internal_exc=None,
                    )
                    return DispatchResult(ok=False, reply=msg, denied_reason="policy_denied", modifications=dict(getattr(pdec, "modifications", {}) or {}))
                policy_mods = dict(getattr(pdec, "modifications", {}) or {})
            except Exception:
                policy_mods = {}

        if self.event_bus is not None:
            try:
                self.event_bus.publish_nowait(
                    BaseEvent(
                        event_type="intent.routed",
                        trace_id=trace_id,
                        source_subsystem=SourceSubsystem.dispatcher,
                        severity=EventSeverity.INFO,
                        payload={"intent_id": intent_id, "module_id": module_id},
                    )
                )
            except Exception:
                pass

        # Touch admin session on successful execution path.
        if self.security.is_admin():
            self.security.touch_admin()

        try:
            # Apply policy modifications into execution context (restrictions only).
            mods = {}
            try:
                mods = dict(getattr(dec, "modifications", {}) or {}) if "dec" in locals() else {}
            except Exception:
                mods = {}
            if policy_mods:
                try:
                    mods = {**dict(mods or {}), **dict(policy_mods or {})}
                except Exception:
                    mods = dict(mods or {})
            if mods:
                context = dict(context or {})
                context["policy"] = redact(mods)
            self.event_logger.log(trace_id, "dispatch.execute", {"module_id": module_id, "intent_id": intent_id})
            exec_mode = str((mod.meta or {}).get("execution_mode") or "inline")
            exec_ctx = dict(context or {})
            # Process execution requires JSON-safe context; thread/inline can accept richer objects.
            if str(exec_mode).lower() == "process":
                exec_ctx = self._jsonable_dict(exec_ctx)
                args = self._jsonable_dict(args)
            out = self._execute_handler(execution_mode=exec_mode, handler=mod.handler, module_path=str(getattr(mod, "module_path", "") or ""), intent_id=intent_id, args=args, context=exec_ctx)
            return DispatchResult(ok=True, reply="", module_output=out, modifications=mods or {})
        except Exception as e:  # noqa: BLE001
            je = self.error_reporter.report_exception(e, trace_id=trace_id, subsystem="dispatcher", context={"intent_id": intent_id, "module_id": module_id})
            self.logger.error(f"[{trace_id}] Module error: {je.code}")
            self.event_logger.log(trace_id, "dispatch.error", {"intent_id": intent_id, "module_id": module_id, "error_code": je.code})
            return DispatchResult(ok=False, reply=je.user_message, denied_reason=je.code)

