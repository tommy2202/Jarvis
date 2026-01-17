from __future__ import annotations

import multiprocessing
import traceback
import contextvars
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

from jarvis.core.events import EventLogger
from jarvis.core.events import redact
from jarvis.core.module_registry import LoadedModule, ModuleRegistry
from jarvis.core.security import PermissionPolicy, SecurityManager
from jarvis.core.error_reporter import ErrorReporter
from jarvis.core.errors import AdminRequiredError, JarvisError
from jarvis.core.capabilities.models import RequestContext, RequestSource
from jarvis.core.events.models import BaseEvent, EventSeverity, SourceSubsystem
from jarvis.core.privacy.gates import PrivacyGate, persistence_context
from jarvis.core.limits.limiter import Limiter
from jarvis.core.trace import reset_trace_id, set_trace_id
from jarvis.core.ux.primitives import acknowledge, completed, failed


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
    remediation: Optional[str] = None
    ux_events: Optional[List[Dict[str, Any]]] = None


@dataclass(frozen=True)
class JobSubmitResult:
    ok: bool
    job_id: Optional[str] = None
    reply: str = ""
    denied_reason: Optional[str] = None
    remediation: str = ""
    required_capabilities: List[str] | None = None


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
        job_manager: Any = None,
        privacy_store: Any = None,
        identity_manager: Any = None,
        limiter: Limiter | None = None,
        feature_flags: Any = None,
        lockdown_manager: Any = None,
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
        self.job_manager = job_manager
        self.privacy_store = privacy_store
        self.identity_manager = identity_manager
        self._privacy_gate = PrivacyGate(privacy_store=privacy_store) if privacy_store is not None else None
        self.limiter = limiter
        self.feature_flags = feature_flags
        self.lockdown_manager = lockdown_manager

    @staticmethod
    def _ux_action_label(intent_id: str, module_id: str) -> str:
        action = str(intent_id or "").strip()
        if not action:
            action = str(module_id or "request").strip()
        return action.replace(".", " ")

    def _emit_ux_event(self, trace_id: str, event_type: str, payload: Dict[str, Any], *, severity: EventSeverity) -> None:
        if self.event_bus is None:
            return
        try:
            self.event_bus.publish_nowait(
                BaseEvent(
                    event_type=event_type,
                    trace_id=trace_id,
                    source_subsystem=SourceSubsystem.dispatcher,
                    severity=severity,
                    payload=payload,
                )
            )
        except Exception:
            pass

    def _emit_job_submit_event(
        self,
        trace_id: str,
        *,
        allowed: bool,
        source: str,
        kind: str,
        required_caps: List[str],
        args: Dict[str, Any],
        denied_caps: Optional[List[str]] = None,
        reason: str = "",
        remediation: str = "",
    ) -> None:
        payload = {
            "trace_id": trace_id,
            "source": source,
            "kind": kind,
            "required_caps": list(required_caps or []),
            "args": redact(args or {}),
        }
        if not allowed:
            payload["denied_caps"] = list(denied_caps or [])
            payload["reason"] = str(reason or "")[:200]
            payload["remediation"] = str(remediation or "")[:200]
        self.event_logger.log(trace_id, "job.submit.allowed" if allowed else "job.submit.denied", payload)
        if self.event_bus is None:
            return
        try:
            self.event_bus.publish_nowait(
                BaseEvent(
                    event_type="job.submit.allowed" if allowed else "job.submit.denied",
                    trace_id=trace_id,
                    source_subsystem=SourceSubsystem.dispatcher,
                    severity=EventSeverity.INFO if allowed else EventSeverity.WARN,
                    payload=payload,
                )
            )
        except Exception:
            pass

    def _start_ux_events(
        self,
        trace_id: str,
        *,
        intent_id: str,
        module_id: str,
        context: Dict[str, Any],
    ) -> Tuple[List[Dict[str, Any]], str]:
        action = self._ux_action_label(intent_id, module_id)
        payload = acknowledge(action)
        payload.update({"intent_id": intent_id, "module_id": module_id, "trace_id": trace_id})
        src = str((context or {}).get("source") or "")
        if src:
            payload["source"] = src
        ux_events = [payload]
        self._emit_ux_event(trace_id, "ux.acknowledge", payload, severity=EventSeverity.INFO)
        return ux_events, action

    def _append_ux_completed(
        self,
        ux_events: List[Dict[str, Any]],
        *,
        trace_id: str,
        intent_id: str,
        module_id: str,
        action: str,
        summary: str,
    ) -> None:
        payload = completed(summary)
        payload.update({"intent_id": intent_id, "module_id": module_id, "action": action, "trace_id": trace_id})
        ux_events.append(payload)
        self._emit_ux_event(trace_id, "ux.completed", payload, severity=EventSeverity.INFO)

    def _append_ux_failed(
        self,
        ux_events: List[Dict[str, Any]],
        *,
        trace_id: str,
        intent_id: str,
        module_id: str,
        action: str,
        reason: str,
        remediation: str,
        denied_reason: Optional[str] = None,
        severity: EventSeverity = EventSeverity.WARN,
    ) -> None:
        remediation = remediation or "Review logs for details."
        payload = failed(reason, remediation)
        payload.update({"intent_id": intent_id, "module_id": module_id, "action": action, "trace_id": trace_id})
        if denied_reason:
            payload["denied_reason"] = denied_reason
        ux_events.append(payload)
        self._emit_ux_event(trace_id, "ux.failed", payload, severity=severity)

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
        ux_events: Optional[List[Dict[str, Any]]] = None,
        ux_action: str = "",
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
        if self.lockdown_manager is not None:
            try:
                self.lockdown_manager.record_deny(
                    trace_id=trace_id,
                    intent_id=intent_id,
                    module_id=module_id,
                    denied_reason=denied_reason,
                    source="dispatcher",
                )
            except Exception:
                pass
        # Safe user message (+ short remediation if provided)
        reason_text = str(reply or "I can’t do that right now.")
        msg = reason_text
        if remediation:
            msg = f"{msg} ({remediation})"
        self.error_reporter.write_error(
            JarvisError(code="permission_denied", user_message=msg[:300], context={"intent_id": intent_id, "module_id": module_id, "reason": denied_reason}),
            trace_id=trace_id,
            subsystem="dispatcher",
            internal_exc=None,
        )
        if ux_events is not None:
            self._append_ux_failed(
                ux_events,
                trace_id=trace_id,
                intent_id=intent_id,
                module_id=module_id,
                action=ux_action or self._ux_action_label(intent_id, module_id),
                reason=reason_text,
                remediation=remediation,
                denied_reason=denied_reason,
            )
        return DispatchResult(
            ok=False,
            reply=msg[:300],
            denied_reason=denied_reason,
            remediation=remediation,
            ux_events=ux_events,
        )

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

    def _build_job_request_context(self, trace_id: str, *, intent_id: str, required_caps: List[str], context: Dict[str, Any]) -> RequestContext:
        client = (context or {}).get("client") or {}
        source_s = str((context or {}).get("source") or client.get("source") or client.get("name") or "cli").lower()
        if source_s not in {"voice", "cli", "web", "ui", "system"}:
            source_s = "cli"
        shutting_down = bool((context or {}).get("shutting_down", False))
        safe_mode = bool((context or {}).get("safe_mode", False))
        client_id = str(client.get("id") or client.get("client_id") or "")
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

        req_caps = list(required_caps or [])
        resource_intensive = bool("CAP_HEAVY_COMPUTE" in req_caps)
        network_requested = bool("CAP_NETWORK_ACCESS" in req_caps)

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
            network_requested=network_requested,
            extra_required_capabilities=req_caps,
            secure_store_mode=secure_mode,
            confirmed=bool((context or {}).get("confirmed", False)),
        )

    def _job_submit_denied(
        self,
        trace_id: str,
        *,
        source: str,
        kind: str,
        required_caps: List[str],
        denied_reason: str,
        reply: str,
        remediation: str = "",
        denied_caps: Optional[List[str]] = None,
        args: Optional[Dict[str, Any]] = None,
    ) -> JobSubmitResult:
        self._emit_job_submit_event(
            trace_id,
            allowed=False,
            source=source,
            kind=kind,
            required_caps=required_caps,
            args=dict(args or {}),
            denied_caps=list(denied_caps or []),
            reason=denied_reason,
            remediation=remediation,
        )
        return JobSubmitResult(
            ok=False,
            job_id=None,
            reply=str(reply or "")[:300],
            denied_reason=denied_reason,
            remediation=str(remediation or "")[:300],
            required_capabilities=list(required_caps or []),
        )

    def submit_job(
        self,
        trace_id: str,
        kind: str,
        args: Dict[str, Any],
        dispatch_context: Dict[str, Any],
        *,
        priority: int = 50,
        max_runtime_seconds: Optional[int] = None,
    ) -> JobSubmitResult:
        token = set_trace_id(trace_id)
        try:
            context = dict(dispatch_context or {})
            source = str((context or {}).get("source") or "cli").lower()
            if source not in {"voice", "cli", "web", "ui", "system"}:
                source = "cli"

            if self.lockdown_manager is not None and self.lockdown_manager.is_active():
                context["safe_mode"] = True
                return self._job_submit_denied(
                    trace_id,
                    source=source,
                    kind=str(kind),
                    required_caps=[],
                    denied_reason="lockdown_active",
                    reply="Lockdown mode active. Job submission is restricted.",
                    remediation="Admin can exit lockdown explicitly.",
                    args=args,
                )

            if self.job_manager is None:
                return self._job_submit_denied(
                    trace_id,
                    source=source,
                    kind=str(kind),
                    required_caps=[],
                    denied_reason="job_manager_unavailable",
                    reply="Job system unavailable.",
                    remediation="Start the job manager before submitting jobs.",
                    args=args,
                )

            meta = self.job_manager.get_kind_metadata(str(kind)) if hasattr(self.job_manager, "get_kind_metadata") else None
            if meta is None:
                return self._job_submit_denied(
                    trace_id,
                    source=source,
                    kind=str(kind),
                    required_caps=[],
                    denied_reason="unknown_job_kind",
                    reply="Unknown job kind.",
                    remediation="Check the job kind allowlist.",
                    args=args,
                )

            required_caps = list(getattr(meta, "required_capabilities", []) or [])
            if bool(getattr(meta, "heavy", False)) and "CAP_HEAVY_COMPUTE" not in required_caps:
                required_caps.append("CAP_HEAVY_COMPUTE")
            if bool(getattr(meta, "requires_admin", False)) and "CAP_ADMIN_ACTION" not in required_caps:
                required_caps.append("CAP_ADMIN_ACTION")

            if self.capability_engine is None:
                return self._job_submit_denied(
                    trace_id,
                    source=source,
                    kind=str(kind),
                    required_caps=required_caps,
                    denied_reason="capability_engine_missing",
                    reply="I can’t submit jobs because enforcement is not configured.",
                    remediation="Initialize the capability engine (config/capabilities.json).",
                    args=args,
                )

            ctx = self._build_job_request_context(trace_id, intent_id="system.job.submit", required_caps=required_caps, context=context)

            # Core limits (runaway protection) — deny before capability/policy evaluation.
            if self.limiter is not None:
                try:
                    diagnostics_override = bool((context or {}).get("diagnostics_override") or (context or {}).get("diagnostics", False))
                    dec0 = self.limiter.allow(
                        source=str(getattr(ctx, "source").value if getattr(ctx, "source", None) is not None else "cli"),
                        intent_id=str(ctx.intent_id),
                        user_id=str(getattr(ctx, "user_id", "default")),
                        client_id=getattr(ctx, "client_id", None),
                        is_admin=bool(getattr(ctx, "is_admin", False)),
                        diagnostics_override=bool(diagnostics_override),
                    )
                    if not bool(dec0.allowed):
                        retry_s = float(getattr(dec0, "retry_after_seconds", 0.0) or 0.0)
                        remediation = f"Wait {max(0.0, retry_s):.1f}s and try again."
                        return self._job_submit_denied(
                            trace_id,
                            source=source,
                            kind=str(kind),
                            required_caps=required_caps,
                            denied_reason="rate_limited",
                            reply="I’m throttling requests to prevent overload.",
                            remediation=remediation,
                            denied_caps=[],
                            args=args,
                        )
                except Exception:
                    pass

            dec = self.capability_engine.evaluate(ctx)
            self.event_logger.log(
                trace_id,
                "dispatch.job.capabilities",
                {"allowed": dec.allowed, "required": dec.required_capabilities, "denied": dec.denied_capabilities, "reasons": dec.reasons, "remediation": dec.remediation[:200]},
            )
            if not bool(dec.allowed):
                return self._job_submit_denied(
                    trace_id,
                    source=source,
                    kind=str(kind),
                    required_caps=list(dec.required_capabilities or required_caps),
                    denied_reason="capability_denied",
                    reply="Job submission denied.",
                    remediation=str(dec.remediation or "")[:200],
                    denied_caps=list(dec.denied_capabilities or []),
                    args=args,
                )

            # Policy decision (restriction-only layer)
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
                        intent_id=ctx.intent_id,
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
                        if bool(getattr(pdec, "require_confirmation", False)):
                            return self._job_submit_denied(
                                trace_id,
                                source=source,
                                kind=str(kind),
                                required_caps=list(dec.required_capabilities or required_caps),
                                denied_reason="confirmation_required",
                                reply=str(pdec.remediation or "Confirmation required.")[:300],
                                remediation="Reply 'confirm' to proceed or 'cancel' to abort.",
                                args=args,
                            )
                        return self._job_submit_denied(
                            trace_id,
                            source=source,
                            kind=str(kind),
                            required_caps=list(dec.required_capabilities or required_caps),
                            denied_reason="policy_denied",
                            reply="Job submission denied.",
                            remediation=str(pdec.remediation or pdec.final_reason or "Denied by policy.")[:200],
                            args=args,
                        )
                except Exception:
                    pass

            if self.security.is_admin():
                self.security.touch_admin()

            client = (context or {}).get("client") or {}
            client_id = str(client.get("id") or client.get("client_id") or "")
            requested_by = {"source": source, "client_id": client_id}
            try:
                job_id = self.job_manager.submit_job(
                    str(kind),
                    args or {},
                    requested_by=requested_by,
                    priority=int(priority),
                    max_runtime_seconds=max_runtime_seconds,
                    trace_id=trace_id,
                    internal_call=True,
                )
            except ValueError as e:
                return self._job_submit_denied(
                    trace_id,
                    source=source,
                    kind=str(kind),
                    required_caps=list(dec.required_capabilities or required_caps),
                    denied_reason="job_submit_invalid",
                    reply=str(e),
                    remediation="Validate job arguments and try again.",
                    args=args,
                )
            self._emit_job_submit_event(
                trace_id,
                allowed=True,
                source=source,
                kind=str(kind),
                required_caps=list(dec.required_capabilities or required_caps),
                args=args,
            )
            return JobSubmitResult(ok=True, job_id=str(job_id), reply="", denied_reason=None, remediation="", required_capabilities=list(dec.required_capabilities or required_caps))
        finally:
            reset_trace_id(token)

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
            "feature_flag": per_intent.get("feature_flag", mod_meta.get("feature_flag")),
            "feature_flags": per_intent.get("feature_flags", mod_meta.get("feature_flags")),
        }

    @staticmethod
    def _normalize_feature_flags(contract: Dict[str, Any]) -> List[str]:
        flags = contract.get("feature_flags")
        if flags is None:
            flags = contract.get("feature_flag")
        if isinstance(flags, str):
            return [flags]
        if isinstance(flags, list):
            return [str(x) for x in flags if isinstance(x, str) and x]
        return []

    def execute_loaded_module(
        self,
        loaded: LoadedModule,
        *,
        intent_id: str,
        args: Dict[str, Any],
        context: Dict[str, Any],
        persist_allowed: bool,
    ) -> Dict[str, Any]:
        """
        Safe execution facade for module handlers.
        Use this instead of accessing LoadedModule.handler directly.
        """
        handler = getattr(loaded, "_unsafe_handler", None)
        if not callable(handler):
            raise RuntimeError("Loaded module missing handler.")
        # Lightweight runtime lint: mark dispatcher-owned execution path.
        ctx = dict(context or {})
        ctx["_dispatcher_execute"] = True
        with persistence_context(persist_allowed=persist_allowed):
            return loaded._call_unsafe(intent_id=intent_id, args=args, context=ctx)

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
        token = set_trace_id(trace_id)
        try:
            context = dict(context or {})
            ux_events, ux_action = self._start_ux_events(trace_id, intent_id=intent_id, module_id=module_id, context=context)
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
                                    "user_id": str(context.get("user_id") or ""),
                                },
                                ux_events=ux_events,
                                ux_action=ux_action,
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
                            ux_events=ux_events,
                            ux_action=ux_action,
                        )

            mod = self.registry.get_by_id(module_id)
            if not mod:
                self.event_logger.log(trace_id, "dispatch.refused", {"reason": "unknown module_id", "module_id": module_id})
                if self.telemetry is not None:
                    try:
                        self.telemetry.increment_counter("errors_total", 1, tags={"subsystem": "dispatcher", "severity": "WARN"})
                    except Exception:
                        pass
                reason = "I can’t execute that module."
                remediation = "Check that the module is installed and enabled."
                self._append_ux_failed(
                    ux_events,
                    trace_id=trace_id,
                    intent_id=intent_id,
                    module_id=module_id,
                    action=ux_action,
                    reason=reason,
                    remediation=remediation,
                    denied_reason="unknown_module",
                )
                return DispatchResult(
                    ok=False,
                    reply=reason,
                    denied_reason="unknown_module",
                    remediation=remediation,
                    ux_events=ux_events,
                )

            # Dispatcher is the single authoritative execution gate:
            # - deny-by-default for unmapped intents
            # - enforce module contract metadata (non-core)
            # - evaluate capability engine first, then policy engine may only further restrict
            if self.lockdown_manager is not None and self.lockdown_manager.is_active():
                context["safe_mode"] = True
                return self._deny(
                    trace_id,
                    intent_id=intent_id,
                    module_id=module_id,
                    denied_reason="lockdown_active",
                    reply="Lockdown mode active. Module execution is restricted.",
                    remediation="Admin can exit lockdown explicitly.",
                    details={"lockdown": True, "module_id": module_id},
                    ux_events=ux_events,
                    ux_action=ux_action,
                )
            if self.capability_engine is None:
                return self._deny(
                    trace_id,
                    intent_id=intent_id,
                    module_id=module_id,
                    denied_reason="capability_engine_missing",
                    reply="I can’t execute actions because enforcement is not configured.",
                    remediation="Initialize the capability engine (config/capabilities.json) before executing intents.",
                    ux_events=ux_events,
                    ux_action=ux_action,
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
                    ux_events=ux_events,
                    ux_action=ux_action,
                )

            # Module contract enforcement (non-core)
            contract = self._resolve_intent_contract(mod.meta or {}, intent_id)
            required_flags = self._normalize_feature_flags(contract)
            if required_flags:
                if self.feature_flags is None:
                    return self._deny(
                        trace_id,
                        intent_id=intent_id,
                        module_id=module_id,
                        denied_reason="feature_flags_unavailable",
                        reply="Feature flags are not configured.",
                        remediation="Initialize feature flags before executing this intent.",
                        details={"required_flags": list(required_flags)},
                        ux_events=ux_events,
                        ux_action=ux_action,
                    )
                disabled = [f for f in required_flags if not bool(getattr(self.feature_flags, "is_enabled", lambda _f: False)(f))]
                if disabled:
                    flag = disabled[0]
                    return self._deny(
                        trace_id,
                        intent_id=intent_id,
                        module_id=module_id,
                        denied_reason="feature_flag_disabled",
                        reply=f"Feature flag disabled: {flag}.",
                        remediation=f"Enable flag '{flag}' to proceed.",
                        details={"disabled_flags": disabled, "required_flags": list(required_flags)},
                        ux_events=ux_events,
                        ux_action=ux_action,
                    )
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
                        ux_events=ux_events,
                        ux_action=ux_action,
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
                        ux_events=ux_events,
                        ux_action=ux_action,
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
                        ux_events=ux_events,
                        ux_action=ux_action,
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
                        ux_events=ux_events,
                        ux_action=ux_action,
                    )

            # Build context (includes source/is_admin/safe_mode/shutting_down/trace_id)
            ctx = self._build_request_context(trace_id, intent_id=intent_id, mod_meta=(mod.meta or {}), context=(context or {}))

            # Core limits (runaway protection) — deny before capability/policy evaluation.
            if self.limiter is not None:
                try:
                    diagnostics_override = bool((context or {}).get("diagnostics_override") or (context or {}).get("diagnostics", False))
                    dec0 = self.limiter.allow(
                        source=str(getattr(ctx, "source").value if getattr(ctx, "source", None) is not None else "cli"),
                        intent_id=str(intent_id),
                        user_id=str(getattr(ctx, "user_id", "default")),
                        client_id=getattr(ctx, "client_id", None),
                        is_admin=bool(getattr(ctx, "is_admin", False)),
                        diagnostics_override=bool(diagnostics_override),
                    )
                    if not bool(dec0.allowed):
                        retry_s = float(getattr(dec0, "retry_after_seconds", 0.0) or 0.0)
                        remediation = f"Wait {max(0.0, retry_s):.1f}s and try again."
                        return self._deny(
                            trace_id,
                            intent_id=intent_id,
                            module_id=module_id,
                            denied_reason="rate_limited",
                            reply="I’m throttling requests to prevent overload.",
                            remediation=remediation,
                            details={"limit_scope": getattr(dec0, "scope", ""), "retry_after_seconds": retry_s, "user_id": getattr(ctx, "user_id", "default")},
                            ux_events=ux_events,
                            ux_action=ux_action,
                        )
                except Exception:
                    # Fail-safe: do not block execution if limiter is unhealthy.
                    pass

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
                    ux_events=ux_events,
                    ux_action=ux_action,
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
                            reply = str(pdec.remediation or "Confirmation required. Reply 'confirm' to proceed or 'cancel' to abort.")[:300]
                            remediation = "Reply 'confirm' to proceed or 'cancel' to abort."
                            self._append_ux_failed(
                                ux_events,
                                trace_id=trace_id,
                                intent_id=intent_id,
                                module_id=module_id,
                                action=ux_action,
                                reason=reply,
                                remediation=remediation,
                                denied_reason="confirmation_required",
                            )
                            return DispatchResult(
                                ok=False,
                                reply=reply,
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
                                remediation=remediation,
                                ux_events=ux_events,
                            )
                        return self._deny(
                            trace_id,
                            intent_id=intent_id,
                            module_id=module_id,
                            denied_reason="policy_denied",
                            reply="I can’t do that right now.",
                            remediation=str(pdec.remediation or pdec.final_reason or "Denied by policy.")[:200],
                            details={"policy_reason": str(pdec.final_reason or ""), "matched_rule_ids": [m.id for m in (pdec.matched_rules or [])]},
                            ux_events=ux_events,
                            ux_action=ux_action,
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
                context = dict(context or {})
                context.setdefault("trace_id", trace_id)
                # Apply policy modifications into execution context (restrictions only).
                if pmods:
                    context["policy"] = redact(pmods)
                # Privacy gate (persistence only): decide persist_allowed, otherwise force ephemeral mode.
                persist_allowed = True
                if self._privacy_gate is not None:
                    try:
                        persist_allowed = bool(self._privacy_gate.evaluate(dict(context or {}), dict(mod.meta or {})))
                    except Exception:
                        persist_allowed = False
                if not persist_allowed:
                    context["ephemeral"] = True
                    if self.event_bus is not None:
                        try:
                            scopes = []
                            if isinstance((context or {}).get("privacy_scopes"), list):
                                scopes.extend([str(x).lower() for x in (context or {}).get("privacy_scopes") if str(x)])
                            if isinstance((mod.meta or {}).get("privacy_scopes"), list):
                                scopes.extend([str(x).lower() for x in (mod.meta or {}).get("privacy_scopes") if str(x)])
                            scopes = sorted(set([s for s in scopes if s]))
                            self.event_bus.publish_nowait(
                                BaseEvent(
                                    event_type="privacy.ephemeral_forced",
                                    trace_id=trace_id,
                                    source_subsystem=SourceSubsystem.dispatcher,
                                    severity=EventSeverity.WARN,
                                    payload={"intent_id": intent_id, "module_id": module_id, "scopes": scopes, "user_id": getattr(ctx, "user_id", "default")},
                                )
                            )
                        except Exception:
                            pass
                self.event_logger.log(trace_id, "dispatch.execute", {"module_id": module_id, "intent_id": intent_id})
                contract = self._resolve_intent_contract(mod.meta or {}, intent_id)
                exec_mode = str(contract.get("execution_mode") or "inline").lower()
                if exec_mode == "thread":
                    from concurrent.futures import ThreadPoolExecutor

                    with ThreadPoolExecutor(max_workers=1) as ex:
                        # Ensure persistence context propagates into thread execution.
                        cv = contextvars.copy_context()

                        def _run():  # noqa: ANN001
                            return self.execute_loaded_module(mod, intent_id=intent_id, args=args, context=context, persist_allowed=persist_allowed)

                        fut = ex.submit(cv.run, _run)
                        out = fut.result(timeout=30.0)
                elif exec_mode == "process":
                    # process isolation: pass ephemeral flag via context (best effort)
                    ctx = dict(context or {})
                    ctx["_dispatcher_execute"] = True
                    out = self._run_in_subprocess(getattr(mod, "module_path", ""), intent_id, args or {}, ctx)
                else:
                    out = self.execute_loaded_module(mod, intent_id=intent_id, args=args, context=context, persist_allowed=persist_allowed)
                summary = ""
                if isinstance(out, dict):
                    summary = str(out.get("summary") or out.get("message") or "")
                if not summary:
                    summary = f"Completed {ux_action}."
                self._append_ux_completed(
                    ux_events,
                    trace_id=trace_id,
                    intent_id=intent_id,
                    module_id=module_id,
                    action=ux_action,
                    summary=summary,
                )
                return DispatchResult(ok=True, reply="", module_output=out, modifications=pmods or {}, ux_events=ux_events)
            except Exception as e:  # noqa: BLE001
                je = self.error_reporter.report_exception(e, trace_id=trace_id, subsystem="dispatcher", context={"intent_id": intent_id, "module_id": module_id})
                self.logger.error(f"[{trace_id}] Module error: {je.code}")
                self.event_logger.log(trace_id, "dispatch.error", {"intent_id": intent_id, "module_id": module_id, "error_code": je.code})
                remediation = "Review logs for details."
                self._append_ux_failed(
                    ux_events,
                    trace_id=trace_id,
                    intent_id=intent_id,
                    module_id=module_id,
                    action=ux_action,
                    reason=je.user_message,
                    remediation=remediation,
                    denied_reason=je.code,
                    severity=EventSeverity.ERROR,
                )
                return DispatchResult(
                    ok=False,
                    reply=je.user_message,
                    denied_reason=je.code,
                    remediation=remediation,
                    ux_events=ux_events,
                )
        finally:
            reset_trace_id(token)

