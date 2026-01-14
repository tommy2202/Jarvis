from __future__ import annotations

import multiprocessing
import traceback
from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple

from jarvis.core.events import EventLogger
from jarvis.core.events import redact
from jarvis.core.module_registry import ModuleRegistry
from jarvis.core.security import PermissionPolicy, SecurityManager
from jarvis.core.error_reporter import ErrorReporter
from jarvis.core.errors import AdminRequiredError, JarvisError
from jarvis.core.capabilities.models import RequestContext, RequestSource
from jarvis.core.events.models import BaseEvent, EventSeverity, SourceSubsystem


def _dispatcher_subprocess_worker(q, module_path: str, intent_id: str, args: Dict[str, Any], context: Dict[str, Any]) -> None:  # noqa: ANN001
    """
    Top-level worker for multiprocessing spawn (Windows-safe).
    """
    try:
        import importlib

        m = importlib.import_module(module_path)
        h = getattr(m, "handle", None)
        if not callable(h):
            raise RuntimeError(f"{module_path} missing handle()")
        out = h(intent_id=intent_id, args=args, context=context)
        q.put({"ok": True, "out": out})
    except Exception as e:  # noqa: BLE001
        q.put({"ok": False, "error": str(e), "traceback": traceback.format_exc()})


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
        policy_engine: Any = None,
        module_manager: Any = None,
        privacy_store: Any = None,
        identity_manager: Any = None,
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
        self.policy_engine = policy_engine
        self.module_manager = module_manager
        self.privacy_store = privacy_store
        self.identity_manager = identity_manager

    def _policy_engine(self) -> Any:
        # For backwards compatibility with existing wiring, allow the capability engine
        # to hold a reference to the policy engine, but the dispatcher is the sole
        # enforcement gate and invokes policy AFTER capability allow.
        if self.policy_engine is not None:
            return self.policy_engine
        return getattr(self.capability_engine, "policy_engine", None) if self.capability_engine is not None else None

    def _deny(
        self,
        trace_id: str,
        *,
        intent_id: str,
        module_id: str,
        denied_reason: str,
        reply: str,
        remediation: str = "",
        details: Optional[Dict[str, Any]] = None,
    ) -> DispatchResult:
        payload = {
            "intent_id": intent_id,
            "module_id": module_id,
            "denied_reason": denied_reason,
            "remediation": remediation[:300],
            "user_id": str((details or {}).get("user_id") or ""),
            **(details or {}),
        }
        self.event_logger.log(trace_id, "dispatch.denied", payload)
        if self.event_bus is not None:
            try:
                self.event_bus.publish_nowait(
                    BaseEvent(
                        event_type="intent.denied",
                        trace_id=trace_id,
                        source_subsystem=SourceSubsystem.dispatcher,
                        severity=EventSeverity.WARN,
                        payload=payload,
                    )
                )
            except Exception:
                pass
        # Safe user message (+ short remediation if provided)
        msg = str(reply or "I can’t do that right now.")
        if remediation:
            msg = f"{msg} ({remediation})"
        self.error_reporter.write_error(
            JarvisError(code="permission_denied", user_message=msg[:300], context={"intent_id": intent_id, "module_id": module_id, "reason": denied_reason}),
            trace_id=trace_id,
            subsystem="dispatcher",
            internal_exc=None,
        )
        return DispatchResult(ok=False, reply=msg[:300], denied_reason=denied_reason)

    def _build_request_context(self, trace_id: str, *, intent_id: str, mod_meta: Dict[str, Any], context: Dict[str, Any]) -> RequestContext:
        perms = self.policy.for_intent(intent_id) if self.policy is not None else {}
        resource_intensive = bool(perms.get("resource_intensive", False)) or bool(mod_meta.get("resource_intensive", False))
        network_access = bool(perms.get("network_access", False))

        client = (context or {}).get("client") or {}
        # "source" should be the request origin (cli/web/ui/voice/system); JarvisApp passes this.
        source_s = str((context or {}).get("source") or client.get("source") or client.get("name") or "cli").lower()
        if source_s not in {"voice", "cli", "web", "ui", "system"}:
            source_s = "cli"
        shutting_down = bool((context or {}).get("shutting_down", False))
        safe_mode = bool((context or {}).get("safe_mode", False))
        client_id = str(client.get("id") or client.get("client_id") or "")
        # Identity: prefer explicit context user_id, otherwise use active user if available.
        user_id = str((context or {}).get("user_id") or "")
        if not user_id:
            try:
                im = getattr(self, "identity_manager", None)
                if im is not None:
                    user_id = str(im.get_active_user().user_id)
            except Exception:
                user_id = ""
        if not user_id:
            user_id = "default"

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

        return RequestContext(
            trace_id=trace_id,
            source=RequestSource(source_s),
            client_id=client_id or None,
            user_id=user_id,
            is_admin=bool(self.security.is_admin()),
            safe_mode=safe_mode,
            shutting_down=shutting_down,
            subsystem_health=breaker_status,
            intent_id=intent_id,
            resource_intensive=resource_intensive,
            network_requested=network_access,
            secure_store_mode=secure_mode,
            confirmed=bool((context or {}).get("confirmed", False)),
        )

    @staticmethod
    def _resolve_intent_contract(mod_meta: Dict[str, Any], intent_id: str) -> Dict[str, Any]:
        # Allow either module-level contract fields or per-intent overrides.
        per_intent = {}
        try:
            per_intent = (mod_meta.get("intent_contracts") or {}).get(intent_id) or {}
        except Exception:
            per_intent = {}
        if not isinstance(per_intent, dict):
            per_intent = {}
        return {
            "execution_mode": per_intent.get("execution_mode", mod_meta.get("execution_mode")),
            "resource_class": per_intent.get("resource_class", mod_meta.get("resource_class")),
            "required_capabilities": per_intent.get("required_capabilities", mod_meta.get("required_capabilities")),
            "core": bool(per_intent.get("core", mod_meta.get("core", False))),
        }

    @staticmethod
    def _run_in_subprocess(module_path: str, intent_id: str, args: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Windows-safe subprocess execution helper (spawn-friendly).
        """

        mp = multiprocessing.get_context("spawn")
        q: Any = mp.Queue()
        p = mp.Process(target=_dispatcher_subprocess_worker, args=(q, module_path, intent_id, args, context))
        p.start()
        p.join(timeout=30.0)
        if p.is_alive():
            try:
                p.terminate()
            except Exception:
                pass
            raise RuntimeError("Subprocess execution timed out.")
        res = None
        try:
            res = q.get_nowait()
        except Exception:
            res = None
        if not isinstance(res, dict):
            raise RuntimeError("Subprocess execution failed.")
        if not bool(res.get("ok")):
            raise RuntimeError(str(res.get("error") or "Subprocess error"))
        return res.get("out") or {}

    def dispatch(self, trace_id: str, intent_id: str, module_id: str, args: Dict[str, Any], context: Dict[str, Any]) -> DispatchResult:
        # Hard module install/enable enforcement (core intents exempt).
        if not str(intent_id).startswith("core."):
            mm = getattr(self, "module_manager", None)
            if mm is not None:
                try:
                    st = None
                    try:
                        st = getattr(mm, "get_status", None)(str(module_id), trace_id=trace_id) if callable(getattr(mm, "get_status", None)) else None
                    except Exception:
                        st = None
                    enabled_ok = bool(mm.is_module_enabled(str(module_id)))
                    if st is not None:
                        enabled_ok = bool(getattr(st, "state", None) and getattr(st.state, "value", "") == "INSTALLED_ENABLED")
                    if not enabled_ok:
                        state_s = str(getattr(getattr(st, "state", None), "value", "") or "UNKNOWN")
                        reason_code_s = str(getattr(getattr(st, "reason_code", None), "value", "") or "UNKNOWN")
                        reason_human = str(getattr(st, "reason_human", "") or "Module is not runnable.")
                        remediation = str(getattr(st, "remediation", "") or "Run /modules scan or /modules enable <id>.")
                        # User-safe message includes state + reason; remediation is appended by _deny.
                        reply = f"Module '{module_id}' is {state_s} ({reason_code_s}): {reason_human}"
                        return self._deny(
                            trace_id,
                            intent_id=intent_id,
                            module_id=module_id,
                            denied_reason="module_not_installed_or_disabled",
                            reply=reply,
                            remediation=remediation,
                            details={
                                "module_id": module_id,
                                "module_state": state_s,
                                "module_reason_code": reason_code_s,
                                "module_remediation": remediation[:200],
                                "user_id": str((context or {}).get("user_id") or ""),
                            },
                        )
                except Exception:
                    # fail-safe: deny if module manager is unhealthy
                    return self._deny(
                        trace_id,
                        intent_id=intent_id,
                        module_id=module_id,
                        denied_reason="module_gate_unavailable",
                        reply="Module is not installed/enabled.",
                        remediation="Run /modules scan or /modules enable <id>.",
                    )

        mod = self.registry.get_by_id(module_id)
        if not mod:
            self.event_logger.log(trace_id, "dispatch.refused", {"reason": "unknown module_id", "module_id": module_id})
            if self.telemetry is not None:
                try:
                    self.telemetry.increment_counter("errors_total", 1, tags={"subsystem": "dispatcher", "severity": "WARN"})
                except Exception:
                    pass
            return DispatchResult(ok=False, reply="I can’t execute that module.", denied_reason="unknown module")

        # Dispatcher is the single authoritative execution gate:
        # - deny-by-default for unmapped intents
        # - enforce module contract metadata (non-core)
        # - evaluate capability engine first, then policy engine may only further restrict
        if self.capability_engine is None:
            return self._deny(
                trace_id,
                intent_id=intent_id,
                module_id=module_id,
                denied_reason="capability_engine_missing",
                reply="I can’t execute actions because enforcement is not configured.",
                remediation="Initialize the capability engine (config/capabilities.json) before executing intents.",
            )

        # Hard: intent must be registered in capabilities intent_requirements
        try:
            cap_cfg = getattr(self.capability_engine, "cfg", None)
            intent_map = getattr(cap_cfg, "intent_requirements", {}) if cap_cfg is not None else {}
        except Exception:
            intent_map = {}
        if intent_id not in (intent_map or {}):
            return self._deny(
                trace_id,
                intent_id=intent_id,
                module_id=module_id,
                denied_reason="intent_unmapped",
                reply="I can’t execute that intent.",
                remediation="Intent is not registered in capabilities policy. Add it to config/capabilities.json intent_requirements.",
            )

        # Module contract enforcement (non-core)
        contract = self._resolve_intent_contract(mod.meta or {}, intent_id)
        is_core = bool(contract.get("core")) or str(intent_id).startswith("core.")
        if not is_core:
            missing = []
            if not contract.get("execution_mode"):
                missing.append("execution_mode")
            if not contract.get("resource_class"):
                missing.append("resource_class")
            if contract.get("required_capabilities") is None:
                missing.append("required_capabilities")
            if missing:
                return self._deny(
                    trace_id,
                    intent_id=intent_id,
                    module_id=module_id,
                    denied_reason="module_contract_incomplete",
                    reply="Module contract incomplete.",
                    remediation="Run /modules wizard or update module manifest.",
                    details={"missing_fields": missing, "module_path": getattr(mod, "module_path", "")},
                )

            declared = contract.get("required_capabilities")
            if not isinstance(declared, list) or any(not isinstance(x, str) or not x for x in declared):
                return self._deny(
                    trace_id,
                    intent_id=intent_id,
                    module_id=module_id,
                    denied_reason="module_contract_invalid",
                    reply="Module contract invalid.",
                    remediation="Run /modules wizard or update module manifest.",
                    details={"field": "required_capabilities"},
                )

            required_caps = list((intent_map or {}).get(intent_id) or [])
            if set(declared) != set(required_caps):
                return self._deny(
                    trace_id,
                    intent_id=intent_id,
                    module_id=module_id,
                    denied_reason="module_contract_mismatch",
                    reply="Module contract does not match capabilities policy.",
                    remediation="Update module manifest required_capabilities to match config/capabilities.json intent_requirements.",
                    details={"declared": list(declared), "required": list(required_caps)},
                )

            exec_mode = str(contract.get("execution_mode") or "").lower()
            if exec_mode not in {"inline", "thread", "process"}:
                return self._deny(
                    trace_id,
                    intent_id=intent_id,
                    module_id=module_id,
                    denied_reason="execution_mode_invalid",
                    reply="Module execution mode is unsupported.",
                    remediation="Set execution_mode to one of: inline, thread, process.",
                    details={"execution_mode": contract.get("execution_mode")},
                )

        # Build context (includes source/is_admin/safe_mode/shutting_down/trace_id)
        ctx = self._build_request_context(trace_id, intent_id=intent_id, mod_meta=(mod.meta or {}), context=(context or {}))

        # Capability decision
        dec = self.capability_engine.evaluate(ctx)
        self.event_logger.log(
            trace_id,
            "dispatch.capabilities",
            {"allowed": dec.allowed, "required": dec.required_capabilities, "denied": dec.denied_capabilities, "reasons": dec.reasons, "remediation": dec.remediation[:200]},
        )
        if not bool(dec.allowed):
            msg = "I can’t do that right now."
            remediation = str(dec.remediation or "")[:200]
            if any("admin" in r.lower() for r in (dec.reasons or [])) or str(dec.remediation or "").lower().startswith("unlock admin"):
                msg = AdminRequiredError().user_message
                if not remediation:
                    remediation = "Unlock admin to proceed."
            return self._deny(
                trace_id,
                intent_id=intent_id,
                module_id=module_id,
                denied_reason="capability_denied",
                reply=msg,
                remediation=remediation,
                details={"denied_caps": list(dec.denied_capabilities or []), "reasons": list(dec.reasons or [])},
            )

        # Policy decision (restriction-only layer)
        pmods: Dict[str, Any] = {}
        pe = self._policy_engine()
        if pe is not None:
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
                    source=ctx.source.value,
                    client_id=ctx.client_id,
                    client_ip=None,
                    is_admin=bool(ctx.is_admin),
                    safe_mode=bool(ctx.safe_mode),
                    shutting_down=bool(ctx.shutting_down),
                    secure_store_mode=ctx.secure_store_mode,
                    tags=[("resource_intensive" if ctx.resource_intensive else ""), ("networked" if ctx.network_requested else "")],
                    resource_over_budget=rc,
                    confirmed=bool(getattr(ctx, "confirmed", False)),
                )
                pctx.tags = [t for t in (pctx.tags or []) if t]
                pdec = pe.evaluate(pctx)
                if not bool(pdec.allowed):
                    # Confirmation flow: do not execute until confirmed
                    if bool(getattr(pdec, "require_confirmation", False)):
                        return DispatchResult(
                            ok=False,
                            reply=str(pdec.remediation or "Confirmation required. Reply 'confirm' to proceed or 'cancel' to abort.")[:300],
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
                    return self._deny(
                        trace_id,
                        intent_id=intent_id,
                        module_id=module_id,
                        denied_reason="policy_denied",
                        reply="I can’t do that right now.",
                        remediation=str(pdec.remediation or pdec.final_reason or "Denied by policy.")[:200],
                        details={"policy_reason": str(pdec.final_reason or ""), "matched_rule_ids": [m.id for m in (pdec.matched_rules or [])]},
                    )
                pmods = dict(getattr(pdec, "modifications", {}) or {})
            except Exception:
                pmods = {}

        if self.event_bus is not None:
            try:
                self.event_bus.publish_nowait(
                    BaseEvent(
                        event_type="intent.routed",
                        trace_id=trace_id,
                        source_subsystem=SourceSubsystem.dispatcher,
                        severity=EventSeverity.INFO,
                        payload={"intent_id": intent_id, "module_id": module_id, "user_id": getattr(ctx, "user_id", "default")},
                    )
                )
            except Exception:
                pass

        # Touch admin session on successful execution path.
        if self.security.is_admin():
            self.security.touch_admin()

        try:
            # Apply policy modifications into execution context (restrictions only).
            if pmods:
                context = dict(context or {})
                context["policy"] = redact(pmods)
            # Privacy gate (persistence only): if this execution would store personal data,
            # require consent; otherwise force ephemeral mode (no persistence).
            # Capability/policy enforcement remains authoritative for allow/deny.
            try:
                ps = getattr(self, "privacy_store", None)
                if ps is not None:
                    ctx2 = dict(context or {})
                    scopes = []
                    if isinstance(ctx2.get("privacy_scopes"), list):
                        scopes.extend([str(x).lower() for x in ctx2.get("privacy_scopes") if str(x)])
                    if isinstance((mod.meta or {}).get("privacy_scopes"), list):
                        scopes.extend([str(x).lower() for x in (mod.meta or {}).get("privacy_scopes") if str(x)])
                    scopes = sorted(set([s for s in scopes if s]))
                    if scopes:
                        user_id = str(ctx2.get("user_id") or "default")
                        missing = []
                        restricted = []
                        for sc in scopes:
                            try:
                                if bool(getattr(ps, "is_scope_restricted")(user_id=user_id, scope=sc)):
                                    restricted.append(sc)
                                    continue
                            except Exception:
                                pass
                            try:
                                c = getattr(ps, "get_consent")(user_id=user_id, scope=sc)
                                if not (c and bool(getattr(c, "granted", False))):
                                    missing.append(sc)
                            except Exception:
                                missing.append(sc)
                        if missing or restricted:
                            ctx2["ephemeral"] = True
                            ctx2["ephemeral_reason"] = {"missing_consent": missing, "restricted": restricted}
                            context = ctx2
                            if self.event_bus is not None:
                                try:
                                    self.event_bus.publish_nowait(
                                        BaseEvent(
                                            event_type="privacy.ephemeral_forced",
                                            trace_id=trace_id,
                                            source_subsystem=SourceSubsystem.dispatcher,
                                            severity=EventSeverity.WARN,
                                            payload={"intent_id": intent_id, "module_id": module_id, "scopes": scopes, "missing": missing, "restricted": restricted},
                                        )
                                    )
                                except Exception:
                                    pass
            except Exception:
                pass
            self.event_logger.log(trace_id, "dispatch.execute", {"module_id": module_id, "intent_id": intent_id})
            contract = self._resolve_intent_contract(mod.meta or {}, intent_id)
            exec_mode = str(contract.get("execution_mode") or "inline").lower()
            if exec_mode == "thread":
                from concurrent.futures import ThreadPoolExecutor

                with ThreadPoolExecutor(max_workers=1) as ex:
                    fut = ex.submit(mod.handler, intent_id=intent_id, args=args, context=context)
                    out = fut.result(timeout=30.0)
            elif exec_mode == "process":
                out = self._run_in_subprocess(getattr(mod, "module_path", ""), intent_id, args or {}, context or {})
            else:
                out = mod.handler(intent_id=intent_id, args=args, context=context)
            return DispatchResult(ok=True, reply="", module_output=out, modifications=pmods or {})
        except Exception as e:  # noqa: BLE001
            je = self.error_reporter.report_exception(e, trace_id=trace_id, subsystem="dispatcher", context={"intent_id": intent_id, "module_id": module_id})
            self.logger.error(f"[{trace_id}] Module error: {je.code}")
            self.event_logger.log(trace_id, "dispatch.error", {"intent_id": intent_id, "module_id": module_id, "error_code": je.code})
            return DispatchResult(ok=False, reply=je.user_message, denied_reason=je.code)

