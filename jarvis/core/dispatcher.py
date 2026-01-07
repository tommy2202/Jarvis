from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple

from jarvis.core.events import EventLogger
from jarvis.core.module_registry import ModuleRegistry
from jarvis.core.security import PermissionPolicy, SecurityManager
from jarvis.core.error_reporter import ErrorReporter
from jarvis.core.errors import AdminRequiredError, JarvisError, PermissionDeniedError
from jarvis.core.capabilities.models import RequestContext, RequestSource
from jarvis.core.events.models import BaseEvent, EventSeverity, SourceSubsystem


@dataclass(frozen=True)
class DispatchResult:
    ok: bool
    reply: str
    module_output: Optional[Dict[str, Any]] = None
    denied_reason: Optional[str] = None


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

        # Capability bus is the single enforcement point (authoritative).
        if self.capability_engine is not None:
            perms = self.policy.for_intent(intent_id)
            resource_intensive = bool(perms.get("resource_intensive", False)) or bool(mod.meta.get("resource_intensive", False))
            network_access = bool(perms.get("network_access", False))

            client = (context or {}).get("client") or {}
            source_s = str((context or {}).get("source") or client.get("source") or client.get("name") or "cli").lower()
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
                resource_intensive=resource_intensive,
                network_requested=network_access,
                secure_store_mode=secure_mode,
            )
            dec = self.capability_engine.evaluate(ctx)
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
                # Standard user-facing denial (safe)
                msg = "I can’t do that right now."
                if any("admin" in r.lower() for r in dec.reasons) or dec.remediation.lower().startswith("unlock admin"):
                    err = AdminRequiredError()
                    msg = err.user_message
                self.error_reporter.write_error(JarvisError(code="permission_denied", user_message=msg, context={"intent_id": intent_id, "denied_caps": dec.denied_capabilities}), trace_id=trace_id, subsystem="dispatcher", internal_exc=None)
                return DispatchResult(ok=False, reply=msg, denied_reason="capability_denied")
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

        else:
            # Fallback legacy enforcement if capability engine not configured
            allowed, reason = self._enforce(trace_id, intent_id)
            self.event_logger.log(trace_id, "dispatch.permission_check", {"intent_id": intent_id, "allowed": allowed, "reason": reason})
            if not allowed:
                err = AdminRequiredError()
                self.error_reporter.write_error(err, trace_id=trace_id, subsystem="dispatcher", internal_exc=None)
                return DispatchResult(ok=False, reply=err.user_message, denied_reason=reason)

        # Touch admin session on successful execution path.
        if self.security.is_admin():
            self.security.touch_admin()

        try:
            self.event_logger.log(trace_id, "dispatch.execute", {"module_id": module_id, "intent_id": intent_id})
            out = mod.handler(intent_id=intent_id, args=args, context=context)
            return DispatchResult(ok=True, reply="", module_output=out)
        except Exception as e:  # noqa: BLE001
            je = self.error_reporter.report_exception(e, trace_id=trace_id, subsystem="dispatcher", context={"intent_id": intent_id, "module_id": module_id})
            self.logger.error(f"[{trace_id}] Module error: {je.code}")
            self.event_logger.log(trace_id, "dispatch.error", {"intent_id": intent_id, "module_id": module_id, "error_code": je.code})
            return DispatchResult(ok=False, reply=je.user_message, denied_reason=je.code)

