from __future__ import annotations

from typing import Any, Dict, List, Optional, Tuple

from jarvis.core.capabilities.audit import CapabilityAuditLogger
from jarvis.core.capabilities.defaults import ADMIN_ONLY_CAPS
from jarvis.core.capabilities.models import (
    CapabilitiesConfig,
    CapabilityDecision,
    DecisionSeverity,
    RequestContext,
)
from jarvis.core.events.models import BaseEvent, EventSeverity, SourceSubsystem


class CapabilityEngine:
    """
    Deterministic capability evaluation.
    """

    def __init__(self, *, cfg: CapabilitiesConfig, audit: CapabilityAuditLogger, logger=None, event_bus=None):
        self.cfg = cfg
        self.audit = audit
        self.logger = logger
        self.event_bus = event_bus
        # Optional: resource governor (set by app.py after initialization)
        self.resource_governor = None
        # Optional: policy engine (set by app.py after initialization)
        self.policy_engine = None

    def get_capabilities(self) -> Dict[str, Dict[str, Any]]:
        return {k: v.model_dump() for k, v in self.cfg.capabilities.items()}

    def get_intent_requirements(self) -> Dict[str, List[str]]:
        return {k: list(v) for k, v in (self.cfg.intent_requirements or {}).items()}

    def evaluate(self, ctx: RequestContext) -> CapabilityDecision:
        required = self._required_caps(ctx)
        denied: List[str] = []
        reasons: List[str] = []

        # Unknown intent deny-by-default
        if ctx.intent_id not in self.cfg.intent_requirements:
            return self._deny(
                ctx,
                required_caps=[],
                denied_caps=[],
                reasons=["Unknown intent (deny by default)."],
                remediation="Intent is not registered in capabilities policy. Add it to config/capabilities.json intent_requirements.",
                severity=DecisionSeverity.WARN,
                audit_anyway=True,
            )

        # Hard source safety: web may never perform CAP_ADMIN_ACTION (even if admin)
        if ctx.source.value == "web" and "CAP_ADMIN_ACTION" in required:
            return self._deny(
                ctx,
                required,
                ["CAP_ADMIN_ACTION"],
                ["CAP_ADMIN_ACTION is denied from web (hard rule)."],
                remediation="Use CLI/UI for admin operations.",
                severity=DecisionSeverity.WARN,
                audit_anyway=True,
            )

        # Shutdown rule: deny all except read/audio-output
        if ctx.shutting_down:
            allowed_caps = {"CAP_READ_FILES", "CAP_AUDIO_OUTPUT"}
            if any(c not in allowed_caps for c in required):
                denied = [c for c in required if c not in allowed_caps]
                reasons.append("Shutting down: capability denied.")
                return self._deny(ctx, required, denied, reasons, remediation="Wait for shutdown to complete.", severity=DecisionSeverity.WARN, audit_anyway=True)

        # Safe mode denies
        if ctx.safe_mode:
            sm_deny = set(self.cfg.safe_mode.deny or [])
            sm_hit = [c for c in required if c in sm_deny]
            if sm_hit:
                return self._deny(ctx, required, sm_hit, ["Safe mode: capability denied."], remediation="Disable safe mode to proceed.", severity=DecisionSeverity.WARN, audit_anyway=True)

        # Source policy denies + require_admin_for
        pol = self.cfg.source_policies.get(ctx.source.value)
        if pol is not None:
            denied_by_source = [c for c in required if c in set(pol.deny or [])]
            if denied_by_source:
                return self._deny(ctx, required, denied_by_source, [f"Source policy denies: {ctx.source.value}"], remediation="Use CLI/UI or change policy.", severity=DecisionSeverity.WARN, audit_anyway=True)
            # require_admin_for
            if not ctx.is_admin:
                req_admin_caps = set(pol.require_admin_for or [])
                hit = [c for c in required if c in req_admin_caps]
                if hit:
                    return self._deny(ctx, required, hit, [f"Source policy requires admin for: {ctx.source.value}"], remediation="Unlock admin to proceed.", severity=DecisionSeverity.WARN, audit_anyway=True)
            # allow all non-sensitive
            if pol.allow_all_non_sensitive and not ctx.is_admin:
                non_sensitive = [c for c in required if self.cfg.capabilities.get(c) and self.cfg.capabilities[c].sensitivity.value == "normal"]
                sensitive = [c for c in required if c not in non_sensitive]
                if sensitive:
                    return self._deny(ctx, required, sensitive, ["Sensitive capability requires admin."], remediation="Unlock admin to proceed.", severity=DecisionSeverity.WARN, audit_anyway=True)

        # Hard admin-only caps (non-negotiable)
        if not ctx.is_admin:
            hard_hit = [c for c in required if c in ADMIN_ONLY_CAPS]
            if hard_hit:
                return self._deny(ctx, required, hard_hit, ["Admin required for high-sensitivity capability."], remediation="Unlock admin to proceed.", severity=DecisionSeverity.WARN, audit_anyway=True)

        # CAP_ADMIN_ACTION always requires admin
        if "CAP_ADMIN_ACTION" in required and not ctx.is_admin:
            return self._deny(ctx, required, ["CAP_ADMIN_ACTION"], ["Admin required."], remediation="Unlock admin to proceed.", severity=DecisionSeverity.WARN, audit_anyway=True)

        # Heavy compute fail-safe rule:
        # - requires admin unless explicitly whitelisted AND source != web
        if "CAP_HEAVY_COMPUTE" in required and not ctx.is_admin:
            if ctx.source.value == "web":
                return self._deny(ctx, required, ["CAP_HEAVY_COMPUTE"], ["Heavy compute denied from web without admin."], remediation="Use CLI/UI with admin or whitelist intent.", severity=DecisionSeverity.WARN, audit_anyway=True)
            if ctx.intent_id not in set(self.cfg.heavy_compute_whitelist_intents or []):
                return self._deny(ctx, required, ["CAP_HEAVY_COMPUTE"], ["Heavy compute requires admin (fail-safe)."], remediation="Unlock admin or whitelist this intent.", severity=DecisionSeverity.WARN, audit_anyway=True)

        # Secure store KEY_MISSING blocks requires_secrets caps
        if (ctx.secure_store_mode or "").upper() == "KEY_MISSING":
            needs_secrets = [c for c in required if self.cfg.capabilities.get(c) and bool(self.cfg.capabilities[c].requires_secrets)]
            if needs_secrets:
                return self._deny(ctx, required, needs_secrets, ["USB key missing: secrets-dependent capability denied."], remediation="Insert USB key to enable secure features.", severity=DecisionSeverity.WARN, audit_anyway=True)

        # Circuit breaker gating (if provided)
        denied_by_breaker = self._deny_by_breakers(ctx, required)
        if denied_by_breaker:
            return self._deny(ctx, required, denied_by_breaker, ["Subsystem temporarily disabled (circuit breaker open)."], remediation="Wait for cooldown or fix underlying issue.", severity=DecisionSeverity.WARN, audit_anyway=True)

        # Resource governor admission control (deterministic, local-only)
        rg = getattr(self, "resource_governor", None)
        if rg is not None:
            try:
                # Only consult for potentially heavy/dangerous capabilities.
                gate_caps = {"CAP_HEAVY_COMPUTE", "CAP_RUN_SUBPROCESS", "CAP_NETWORK_ACCESS"}
                if any(c in gate_caps for c in required):
                    adm = rg.admit(operation="intent.execute", trace_id=ctx.trace_id, required_caps=list(required), allow_delay=False)
                    if not bool(adm.allowed):
                        return self._deny(
                            ctx,
                            required,
                            [c for c in required if c in gate_caps],
                            list(adm.reasons or []) + [f"Resource governor action: {adm.action.value}"],
                            remediation=str(adm.remediation or "System is under resource pressure. Try again later."),
                            severity=DecisionSeverity.WARN,
                            audit_anyway=True,
                        )
            except Exception:
                pass

        # Default policy check
        for c in required:
            cap = self.cfg.capabilities.get(c)
            if cap is None:
                denied.append(c)
                reasons.append("Unknown capability in requirements.")
                continue
            if cap.requires_admin and not ctx.is_admin:
                denied.append(c)
                reasons.append("Capability requires admin.")
                continue
            if cap.default_policy.value == "deny" and not ctx.is_admin and cap.sensitivity.value == "high":
                denied.append(c)
                reasons.append("Denied by default policy.")
                continue

        if denied:
            return self._deny(ctx, required, denied, reasons, remediation="Unlock admin or adjust capability policy.", severity=DecisionSeverity.WARN, audit_anyway=True)

        # Allowed
        dec = CapabilityDecision(
            allowed=True,
            require_confirmation=False,
            modifications={},
            denied_capabilities=[],
            required_capabilities=list(required),
            reasons=["Allowed by capability policy."],
            remediation="",
            severity=DecisionSeverity.INFO,
            audit_event={
                "source": ctx.source.value,
                "intent_id": ctx.intent_id,
                "required_caps": list(required),
                "allowed": True,
                "safe_mode": bool(ctx.safe_mode),
                "shutting_down": bool(ctx.shutting_down),
            },
        )
        self._audit(ctx, dec, force=False)
        return dec

    # ---- helpers ----
    def _required_caps(self, ctx: RequestContext) -> List[str]:
        req = list(self.cfg.intent_requirements.get(ctx.intent_id) or [])
        extra = list(getattr(ctx, "extra_required_capabilities", []) or [])
        req.extend([str(c).strip() for c in extra if str(c or "").strip()])
        # Legacy flags augmentation (kept minimal):
        if ctx.network_requested and "CAP_NETWORK_ACCESS" not in req:
            req.append("CAP_NETWORK_ACCESS")
        if ctx.resource_intensive and "CAP_HEAVY_COMPUTE" not in req:
            req.append("CAP_HEAVY_COMPUTE")
        return sorted(set(req))

    def _deny_by_breakers(self, ctx: RequestContext, required: List[str]) -> List[str]:
        br = (ctx.subsystem_health or {}).get("breakers") or {}
        if not isinstance(br, dict):
            return []

        cap_to_breaker = {
            "CAP_AUDIO_INPUT": "stt",
            "CAP_AUDIO_OUTPUT": "tts",
            "CAP_NETWORK_ACCESS": "web",
            "CAP_HEAVY_COMPUTE": "llm",
            "CAP_CODE_GENERATION": "llm",
            "CAP_IMAGE_GENERATION": "llm",
        }
        denied = []
        for cap in required:
            b = cap_to_breaker.get(cap)
            if not b:
                continue
            if str(br.get(b) or "").upper() == "OPEN":
                denied.append(cap)
        return denied

    def _deny(
        self,
        ctx: RequestContext,
        required_caps: List[str],
        denied_caps: List[str],
        reasons: List[str],
        remediation: str,
        severity: DecisionSeverity,
        *,
        audit_anyway: bool,
    ) -> CapabilityDecision:
        dec = CapabilityDecision(
            allowed=False,
            denied_capabilities=list(sorted(set(denied_caps))),
            required_capabilities=list(required_caps),
            reasons=list(reasons),
            remediation=remediation,
            severity=severity,
            audit_event={
                "source": ctx.source.value,
                "intent_id": ctx.intent_id,
                "required_caps": list(required_caps),
                "denied_caps": list(sorted(set(denied_caps))),
                "allowed": False,
                "safe_mode": bool(ctx.safe_mode),
                "shutting_down": bool(ctx.shutting_down),
                "secure_store_mode": ctx.secure_store_mode,
            },
        )
        self._audit(ctx, dec, force=audit_anyway)
        return dec

    def _audit(self, ctx: RequestContext, dec: CapabilityDecision, *, force: bool) -> None:
        # Audit if denied, or if any required cap has audit=true, or forced
        audit_caps = any(bool(self.cfg.capabilities.get(c) and self.cfg.capabilities[c].audit) for c in (dec.required_capabilities or []))
        if force or (not dec.allowed) or audit_caps:
            sev = "HIGH" if any(c in ADMIN_ONLY_CAPS for c in (dec.required_capabilities or [])) else ("WARN" if not dec.allowed else "INFO")
            self.audit.log_decision(
                trace_id=ctx.trace_id,
                severity=sev,
                event="capability.decision",
                outcome="allowed" if dec.allowed else "denied",
                details=dec.audit_event,
                ip=None,
                endpoint="dispatcher",
            )
        # Always publish internal capability decision event (for telemetry/UI), redacted payload only.
        if self.event_bus is not None:
            try:
                self.event_bus.publish_nowait(
                    BaseEvent(
                        event_type="capability.decision",
                        trace_id=ctx.trace_id,
                        source_subsystem=SourceSubsystem.dispatcher,
                        severity=EventSeverity.WARN if not dec.allowed else EventSeverity.INFO,
                        payload=dec.audit_event,
                    )
                )
            except Exception:
                pass

