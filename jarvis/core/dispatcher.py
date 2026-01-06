from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple

from jarvis.core.events import EventLogger
from jarvis.core.module_registry import ModuleRegistry
from jarvis.core.security import PermissionPolicy, SecurityManager
from jarvis.core.error_reporter import ErrorReporter
from jarvis.core.errors import AdminRequiredError, JarvisError, PermissionDeniedError


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
    ):
        self.registry = registry
        self.policy = policy
        self.security = security
        self.event_logger = event_logger
        self.logger = logger
        self.error_reporter = error_reporter or ErrorReporter()

    def _enforce(self, trace_id: str, intent_id: str) -> Tuple[bool, str]:
        perms = self.policy.for_intent(intent_id)
        requires_admin = bool(perms.get("requires_admin", False))
        resource_intensive = bool(perms.get("resource_intensive", False))

        # Fail-safe: resource-intensive intents are admin-only
        if resource_intensive:
            requires_admin = True

        if requires_admin and not self.security.is_admin():
            return False, "admin required"
        return True, "ok"

    def dispatch(self, trace_id: str, intent_id: str, module_id: str, args: Dict[str, Any], context: Dict[str, Any]) -> DispatchResult:
        mod = self.registry.get_by_id(module_id)
        if not mod:
            self.event_logger.log(trace_id, "dispatch.refused", {"reason": "unknown module_id", "module_id": module_id})
            return DispatchResult(ok=False, reply="I can’t execute that module.", denied_reason="unknown module")

        # MODULE_META fail-safe: resource_intensive => admin-only regardless of config.
        if bool(mod.meta.get("resource_intensive", False)) and not self.security.is_admin():
            self.event_logger.log(trace_id, "dispatch.denied", {"intent_id": intent_id, "reason": "module resource_intensive requires admin"})
            err = AdminRequiredError()
            self.error_reporter.write_error(err, trace_id=trace_id, subsystem="dispatcher", internal_exc=None)
            return DispatchResult(ok=False, reply=err.user_message, denied_reason="admin required")

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

