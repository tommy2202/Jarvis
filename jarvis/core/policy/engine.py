from __future__ import annotations

import datetime as dt
from typing import Any, Dict, List, Optional

from jarvis.core.events.models import BaseEvent, EventSeverity, SourceSubsystem
from jarvis.core.policy.explanations import best_reason
from jarvis.core.policy.matcher import PolicyMatcher
from jarvis.core.policy.modifiers import merge_modifications
from jarvis.core.policy.models import (
    MatchedRule,
    PolicyConfigFile,
    PolicyContext,
    PolicyDecision,
    PolicyEffect,
    PolicySeverity,
)
from jarvis.core.security_events import SecurityAuditLogger


class PolicyEngine:
    def __init__(
        self,
        *,
        cfg: PolicyConfigFile,
        failsafe: bool = False,
        fail_message: str = "",
        event_bus: Any = None,
        audit_logger: Optional[SecurityAuditLogger] = None,
        matcher: Optional[PolicyMatcher] = None,
    ):
        self.cfg = cfg
        self._failsafe = bool(failsafe)
        self._fail_message = str(fail_message or "")
        self.event_bus = event_bus
        self.audit_logger = audit_logger or SecurityAuditLogger()
        self.matcher = matcher or PolicyMatcher()

    def status(self) -> Dict[str, Any]:
        return {"enabled": bool(self.cfg.enabled), "failsafe": bool(self._failsafe), "error": self._fail_message[:300] if self._failsafe else ""}

    def rules(self) -> list[dict]:
        return [r.model_dump() for r in sorted(self.cfg.rules, key=lambda x: (x.priority, x.id))]

    def get_rule(self, rule_id: str) -> Optional[dict]:
        for r in self.cfg.rules:
            if r.id == rule_id:
                return r.model_dump()
        return None

    def evaluate(self, ctx: PolicyContext) -> PolicyDecision:
        # If config invalid/missing -> FAILSAFE mode
        if self._failsafe:
            dec = self._failsafe_decision(ctx)
            self._emit(ctx, dec)
            return dec

        if not bool(self.cfg.enabled):
            dec = PolicyDecision(allowed=True, final_reason="Policy disabled.", severity=PolicySeverity.INFO)
            self._emit(ctx, dec, minimal=True)
            return dec

        matched: List[MatchedRule] = []
        mods: Dict[str, Any] = {}
        required_admin = False
        require_confirmation = False
        deny_reason: Optional[str] = None
        deny_remediation: str = ""

        for rule in sorted(self.cfg.rules, key=lambda r: (r.priority, r.id)):
            if not self.matcher.matches(ctx, rule.match):
                continue
            matched.append(MatchedRule(id=rule.id, effect=rule.effect, reason=rule.reason, priority=rule.priority))

            if rule.effect == PolicyEffect.DENY:
                deny_reason = rule.reason or f"Denied by policy {rule.id}."
                deny_remediation = rule.remediation or ""
                break

            if rule.effect == PolicyEffect.REQUIRE_ADMIN:
                required_admin = True
                if not ctx.is_admin:
                    deny_reason = rule.reason or "Admin required."
                    deny_remediation = rule.remediation or "Unlock admin to proceed."
                    break

            if rule.effect == PolicyEffect.REQUIRE_CONFIRMATION:
                # Once user has explicitly confirmed, do not re-require confirmation.
                if not bool(ctx.confirmed):
                    require_confirmation = True

            if rule.effect == PolicyEffect.MODIFY and rule.modify is not None:
                mods = merge_modifications(mods, rule.modify.model_dump())

            if rule.effect == PolicyEffect.ALLOW:
                # allow does not override later denies; keep scanning
                continue

        # Defaults (deny unknown/high-sensitivity without admin) are enforced by capability engine;
        # here we only apply explicit rules and safe modifications.
        if deny_reason is not None:
            dec = PolicyDecision(
                allowed=False,
                required_admin=required_admin,
                require_confirmation=require_confirmation,
                modifications=mods,
                matched_rules=matched,
                final_reason=deny_reason,
                remediation=deny_remediation,
                severity=PolicySeverity.WARN,
            )
            self._emit(ctx, dec)
            return dec

        # If confirmation required, deny execution until confirmed (dispatcher enforces flow)
        if require_confirmation:
            dec = PolicyDecision(
                allowed=False,
                required_admin=required_admin,
                require_confirmation=True,
                modifications=mods,
                matched_rules=matched,
                final_reason=(matched[0].reason if matched else "Confirmation required."),
                remediation="Reply 'confirm' to proceed or 'cancel' to abort.",
                severity=PolicySeverity.WARN,
            )
            self._emit(ctx, dec)
            return dec

        dec = PolicyDecision(
            allowed=True,
            required_admin=required_admin,
            require_confirmation=False,
            modifications=mods,
            matched_rules=matched,
            final_reason=(matched[0].reason if matched else "Allowed by policy."),
            remediation="",
            severity=PolicySeverity.INFO,
        )
        self._emit(ctx, dec, minimal=(not matched and not mods))
        return dec

    # ---- internals ----
    def _failsafe_decision(self, ctx: PolicyContext) -> PolicyDecision:
        risky = {"CAP_NETWORK_ACCESS", "CAP_RUN_SUBPROCESS", "CAP_HEAVY_COMPUTE"}
        if any(c in risky for c in (ctx.required_capabilities or [])) and not ctx.is_admin:
            return PolicyDecision(
                allowed=False,
                matched_rules=[],
                final_reason="Policy system is unhealthy; denying risky action (fail-safe).",
                remediation="Fix config/policy.json and restart, or use admin-only override.",
                severity=PolicySeverity.ERROR,
                failsafe=True,
            )
        return PolicyDecision(allowed=True, final_reason="Policy failsafe active (non-risky allowed).", severity=PolicySeverity.WARN, failsafe=True)

    def _emit(self, ctx: PolicyContext, dec: PolicyDecision, *, minimal: bool = False) -> None:
        # Security audit log (privacy-safe)
        try:
            self.audit_logger.log(
                trace_id=ctx.trace_id,
                severity="WARN" if not dec.allowed else "INFO",
                event="policy.decision",
                ip=ctx.client_ip,
                endpoint="dispatcher",
                outcome="denied" if not dec.allowed else "allowed",
                details={
                    "intent_id": ctx.intent_id,
                    "source": ctx.source,
                    "required_caps": list(ctx.required_capabilities or []),
                    "allowed": bool(dec.allowed),
                    "require_confirmation": bool(dec.require_confirmation),
                    "matched_rules": [m.model_dump() for m in dec.matched_rules],
                    "failsafe": bool(dec.failsafe),
                }
                if not minimal
                else {"intent_id": ctx.intent_id, "allowed": bool(dec.allowed)},
            )
        except Exception:
            pass
        # Event bus
        if self.event_bus is not None:
            try:
                self.event_bus.publish_nowait(
                    BaseEvent(
                        event_type="policy.decision",
                        trace_id=ctx.trace_id,
                        source_subsystem=SourceSubsystem.dispatcher,
                        severity=EventSeverity.WARN if not dec.allowed else EventSeverity.INFO,
                        payload={
                            "intent_id": ctx.intent_id,
                            "source": ctx.source,
                            "allowed": bool(dec.allowed),
                            "require_confirmation": bool(dec.require_confirmation),
                            "matched_rule_ids": [m.id for m in dec.matched_rules],
                            "reason": best_reason(dec),
                            "failsafe": bool(dec.failsafe),
                        },
                    )
                )
            except Exception:
                pass

