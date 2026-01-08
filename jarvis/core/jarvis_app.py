from __future__ import annotations

import threading
import time
import uuid
from dataclasses import dataclass
from typing import Any, Dict, Optional

from jarvis.core.core_intents import AmbiguousMatch, CoreIntentRegistry, MatchResult
from jarvis.core.dispatcher import Dispatcher
from jarvis.core.events import EventLogger
from jarvis.core.intent_router import IntentResult, StageAIntentRouter
from jarvis.core.llm_router import StageBLLMRouter


@dataclass(frozen=True)
class MessageResponse:
    trace_id: str
    reply: str
    intent_id: str
    intent_source: str
    confidence: float
    requires_followup: bool
    followup_question: Optional[str]
    modifications: Dict[str, Any] = None  # policy modifications (safe restrictions)


class JarvisApp:
    def __init__(
        self,
        stage_a: StageAIntentRouter,
        stage_b: StageBLLMRouter,
        dispatcher: Dispatcher,
        intent_config_by_id: Dict[str, Dict[str, Any]],
        confirmation_templates: Dict[str, str],
        event_logger: EventLogger,
        logger,
        threshold: float = 0.55,
        telemetry: Any = None,
        core_registry: CoreIntentRegistry | None = None,
        core_fact_fuzzy_cfg: Dict[str, Any] | None = None,
    ):
        self.stage_a = stage_a
        self.stage_b = stage_b
        self.dispatcher = dispatcher
        self.intent_config_by_id = intent_config_by_id
        self.confirmation_templates = confirmation_templates
        self.event_logger = event_logger
        self.logger = logger
        self.threshold = threshold
        self.telemetry = telemetry
        self.core_registry = core_registry or CoreIntentRegistry(fuzzy_cfg=core_fact_fuzzy_cfg or {})
        self._lock = threading.Lock()
        self._pending_confirmations: Dict[str, Dict[str, Any]] = {}
        self._pending_clarifications: Dict[str, Dict[str, Any]] = {}

    def _confirmation_key(self, source: str, client: Optional[Dict[str, Any]]) -> str:
        c = client or {}
        cid = str(c.get("id") or c.get("client_id") or c.get("name") or source or "cli")
        return f"{source}:{cid}"

    def _consume_confirmation(self, key: str) -> Optional[Dict[str, Any]]:
        p = self._pending_confirmations.get(key)
        if not p:
            return None
        if float(p.get("expires_at") or 0) < time.time():
            self._pending_confirmations.pop(key, None)
            return None
        return p

    def _render_confirmation(self, intent_id: str, args: Dict[str, Any]) -> str:
        tmpl = self.confirmation_templates.get(intent_id) or "Okay."
        try:
            return tmpl.format(**args)
        except Exception:  # noqa: BLE001
            return tmpl

    def _consume_clarification(self, key: str) -> Optional[Dict[str, Any]]:
        p = self._pending_clarifications.get(key)
        if not p:
            return None
        if float(p.get("expires_at") or 0) < time.time():
            self._pending_clarifications.pop(key, None)
            return None
        return p

    @staticmethod
    def _parse_clarify_choice(text: str, *, labels: Dict[str, str]) -> Optional[int]:
        t = str(text or "").strip().lower()
        if t in {"1", "first", "one", "option 1", "option1"}:
            return 0
        if t in {"2", "second", "two", "option 2", "option2"}:
            return 1
        # allow label-based replies ("time", "date", ...)
        for idx, intent_id in enumerate(labels.keys()):
            lab = (labels.get(intent_id) or "").strip().lower()
            if lab and (t == lab or t.replace(" ", "") == lab.replace(" ", "")):
                return idx
        return None

    def _handle_core_intent(self, intent_id: str, *, safe_mode: bool, shutting_down: bool) -> str:
        # Core facts: deterministic, local, read-only.
        from datetime import datetime, timezone
        import importlib.metadata

        if intent_id == "core.time.now":
            now = datetime.now().astimezone()
            return now.strftime("It’s %H:%M:%S.")
        if intent_id == "core.date.today":
            now = datetime.now(timezone.utc).astimezone()
            return now.strftime("Today is %Y-%m-%d.")
        if intent_id == "core.status.listening":
            return "Listening."
        if intent_id == "core.status.admin":
            try:
                is_admin = bool(self.dispatcher.security.is_admin())
            except Exception:
                is_admin = False
            return "Admin is unlocked." if is_admin else "Admin is locked."
        if intent_id == "core.status.busy":
            # Conservative: if shutting down, we are busy; otherwise not.
            return "I’m busy right now." if bool(shutting_down) else "I’m not busy."
        if intent_id == "core.status.health":
            if self.telemetry is None:
                return "Health is unknown."
            try:
                rows = self.telemetry.get_health()
            except Exception:
                rows = []
            statuses = {str((r or {}).get("status") or "").upper() for r in (rows or [])}
            if "DOWN" in statuses:
                return "Health: down."
            if "DEGRADED" in statuses:
                return "Health: degraded."
            if "OK" in statuses:
                return "Health: ok."
            return "Health is unknown."
        if intent_id == "core.identity.version":
            v = "unknown"
            try:
                v = importlib.metadata.version("jarvis-offline")
            except Exception:
                v = "unknown"
            return f"Version: {v}."

        # Unknown core intent (should not happen)
        return "OK."

    def _required_missing(self, intent_id: str, args: Dict[str, Any]) -> bool:
        cfg = self.intent_config_by_id.get(intent_id) or {}
        required = cfg.get("required_args") or []
        return any((r not in args or args.get(r) in (None, "")) for r in required)

    def process_message(self, message: str, client: Optional[Dict[str, Any]] = None, *, source: str = "cli", safe_mode: bool = False, shutting_down: bool = False) -> MessageResponse:
        with self._lock:
            trace_id = uuid.uuid4().hex
            self.event_logger.log(trace_id, "request.received", {"message": message, "client": client or {}})

            # Request origin (authoritative). Do NOT overwrite this with router stage labels.
            request_source = str(source or "cli").lower()

            key = self._confirmation_key(source, client)
            normalized = str(message or "").strip().lower()
            if normalized in {"confirm", "cancel"}:
                pending = self._consume_confirmation(key)
                if not pending:
                    return MessageResponse(
                        trace_id=trace_id,
                        reply="Nothing to confirm.",
                        intent_id="system.confirm",
                        intent_source="system",
                        confidence=1.0,
                        requires_followup=False,
                        followup_question=None,
                        modifications={},
                    )
                if normalized == "cancel":
                    self._pending_confirmations.pop(key, None)
                    return MessageResponse(
                        trace_id=trace_id,
                        reply="Canceled.",
                        intent_id=str(pending.get("intent_id") or "unknown"),
                        intent_source="system",
                        confidence=1.0,
                        requires_followup=False,
                        followup_question=None,
                        modifications={},
                    )
                # confirm: execute pending action
                self._pending_confirmations.pop(key, None)
                intent_id = str(pending.get("intent_id") or "unknown")
                module_id = str(pending.get("module_id") or "")
                args = dict(pending.get("args") or {})
                dispatch_context = dict(pending.get("context") or {})
                dispatch_context["confirmed"] = True
                dr = self.dispatcher.dispatch(trace_id, intent_id, module_id, args, dispatch_context)
                if not dr.ok:
                    return MessageResponse(
                        trace_id=trace_id,
                        reply=dr.reply,
                        intent_id=intent_id,
                        intent_source="system",
                        confidence=1.0,
                        requires_followup=False,
                        followup_question=None,
                        modifications=dict(dr.modifications or {}),
                    )
                confirmation = self._render_confirmation(intent_id, args)
                return MessageResponse(
                    trace_id=trace_id,
                    reply=confirmation,
                    intent_id=intent_id,
                    intent_source="system",
                    confidence=1.0,
                    requires_followup=False,
                    followup_question=None,
                    modifications=dict(dr.modifications or {}),
                )

            # Clarification flow (core fact ambiguity)
            pending_clarify = self._consume_clarification(key)
            if pending_clarify is not None:
                choices = list(pending_clarify.get("candidates") or [])
                labels = dict(pending_clarify.get("labels") or {})
                idx = self._parse_clarify_choice(message, labels=labels)
                if idx is None or idx not in {0, 1} or idx >= len(choices):
                    # keep pending, ask again (bounded)
                    prompt = str(pending_clarify.get("prompt") or "Did you mean the first or second option?")
                    return MessageResponse(
                        trace_id=trace_id,
                        reply=prompt,
                        intent_id="system.clarify",
                        intent_source="system",
                        confidence=1.0,
                        requires_followup=True,
                        followup_question="Reply 'first' or 'second'.",
                        modifications={},
                    )
                self._pending_clarifications.pop(key, None)
                chosen = str(choices[idx])
                reply = self._handle_core_intent(chosen, safe_mode=bool(safe_mode), shutting_down=bool(shutting_down))
                return MessageResponse(
                    trace_id=trace_id,
                    reply=reply,
                    intent_id=chosen,
                    intent_source="core",
                    confidence=1.0,
                    requires_followup=False,
                    followup_question=None,
                    modifications={},
                )

            # Core intents (exact phrase match, then core-fact fuzzy safeguard)
            exact = self.core_registry.exact_match(message)
            if exact is not None:
                reply = self._handle_core_intent(exact.intent_id, safe_mode=bool(safe_mode), shutting_down=bool(shutting_down))
                self.event_logger.log(trace_id, "core_intent.exact_matched", {"intent_id": exact.intent_id, "matched_phrase": exact.matched_phrase})
                return MessageResponse(
                    trace_id=trace_id,
                    reply=reply,
                    intent_id=exact.intent_id,
                    intent_source="core",
                    confidence=1.0,
                    requires_followup=False,
                    followup_question=None,
                    modifications={},
                )

            fuzzy = self.core_registry.fuzzy_match_fact_intent(message)
            if isinstance(fuzzy, MatchResult):
                # audit event: fuzzy core fact match used
                self.event_logger.log(
                    trace_id,
                    "core_fact_fuzzy.matched",
                    {"intent_id": fuzzy.intent_id, "score": float(fuzzy.score), "matched_phrase": str(fuzzy.matched_phrase)},
                )
                reply = self._handle_core_intent(fuzzy.intent_id, safe_mode=bool(safe_mode), shutting_down=bool(shutting_down))
                return MessageResponse(
                    trace_id=trace_id,
                    reply=reply,
                    intent_id=fuzzy.intent_id,
                    intent_source="core",
                    confidence=float(fuzzy.score),
                    requires_followup=False,
                    followup_question=None,
                    modifications={},
                )
            if isinstance(fuzzy, AmbiguousMatch):
                a, b = fuzzy.candidates
                # Enter clarification mode (deterministic, local).
                lab_a = self.core_registry.label(a.intent_id)
                lab_b = self.core_registry.label(b.intent_id)
                prompt = f"Did you mean {lab_a} or {lab_b}?"
                self._pending_clarifications[key] = {
                    "expires_at": time.time() + 20.0,
                    "candidates": [a.intent_id, b.intent_id],
                    "labels": {a.intent_id: lab_a, b.intent_id: lab_b},
                    "prompt": prompt,
                }
                self.event_logger.log(
                    trace_id,
                    "core_fact_fuzzy.ambiguous",
                    {"candidates": [{"intent_id": a.intent_id, "score": a.score}, {"intent_id": b.intent_id, "score": b.score}]},
                )
                return MessageResponse(
                    trace_id=trace_id,
                    reply=prompt,
                    intent_id="system.clarify",
                    intent_source="system",
                    confidence=max(float(a.score), float(b.score)),
                    requires_followup=True,
                    followup_question="Reply 'first' or 'second'.",
                    modifications={},
                )

            # Stage A
            t_route0 = time.time()
            a: IntentResult = self.stage_a.route(message)
            self.event_logger.log(trace_id, "router.stage_a", a.model_dump())

            chosen_intent_id: Optional[str] = a.intent_id
            chosen_args: Dict[str, Any] = dict(a.args or {})
            router_source = "stage_a"
            conf = float(a.confidence)

            # Stage B fallback conditions
            needs_b = (
                not chosen_intent_id
                or conf < self.threshold
                or (chosen_intent_id and self._required_missing(chosen_intent_id, chosen_args))
                or (chosen_intent_id and chosen_intent_id not in self.intent_config_by_id)
            )

            if needs_b:
                allowed = {k: {"required_args": (v.get("required_args") or [])} for k, v in self.intent_config_by_id.items()}
                b = self.stage_b.route(message, allowed_intents={**allowed, "unknown": {}})
                self.event_logger.log(trace_id, "router.stage_b", {"ok": bool(b), "raw_validated": bool(b)})
                if b and b.intent in self.intent_config_by_id:
                    chosen_intent_id = b.intent
                    chosen_args = dict(b.args or {})
                    router_source = "stage_b"
                    conf = float(b.confidence)
                else:
                    # Never execute unknown intents
                    if self.telemetry is not None:
                        try:
                            self.telemetry.record_latency("routing_latency_ms", (time.time() - t_route0) * 1000.0, tags={"source": "stage_b"})
                        except Exception:
                            pass
                    return MessageResponse(
                        trace_id=trace_id,
                        reply="I couldn’t map that to a safe action.",
                        intent_id="unknown",
                        intent_source="stage_b",
                        confidence=0.0,
                        requires_followup=False,
                        followup_question=None,
                    )

            assert chosen_intent_id is not None
            if chosen_intent_id not in self.intent_config_by_id:
                self.event_logger.log(trace_id, "router.refused", {"reason": "intent not in registry", "intent_id": chosen_intent_id})
                if self.telemetry is not None:
                    try:
                        self.telemetry.record_latency("routing_latency_ms", (time.time() - t_route0) * 1000.0, tags={"source": router_source})
                    except Exception:
                        pass
                return MessageResponse(
                    trace_id=trace_id,
                    reply="I can’t execute unknown intents.",
                    intent_id="unknown",
                    intent_source=router_source,
                    confidence=conf,
                    requires_followup=False,
                    followup_question=None,
                )

            cfg = self.intent_config_by_id[chosen_intent_id]
            module_id = str(cfg.get("module_id"))
            confirmation = self._render_confirmation(chosen_intent_id, chosen_args)

            requires_followup = self._required_missing(chosen_intent_id, chosen_args)
            followup_question: Optional[str] = None
            if requires_followup:
                # Minimal followup: ask for the first missing arg.
                required = cfg.get("required_args") or []
                for r in required:
                    if r not in chosen_args or chosen_args.get(r) in (None, ""):
                        followup_question = f"What {r}?"
                        break

            # Enforced execution decision happens in dispatcher.
            if self.telemetry is not None:
                try:
                    self.telemetry.record_latency("routing_latency_ms", (time.time() - t_route0) * 1000.0, tags={"source": router_source})
                except Exception:
                    pass
            t_disp0 = time.time()
            dispatch_context = {
                "client": client or {},
                # Authoritative request origin for enforcement (web/ui/cli/voice/system).
                "source": request_source,
                # Diagnostic only; not used for enforcement.
                "router_source": router_source,
                "safe_mode": bool(safe_mode),
                "shutting_down": bool(shutting_down),
            }
            dr = self.dispatcher.dispatch(trace_id, chosen_intent_id, module_id, chosen_args, dispatch_context)
            self.event_logger.log(trace_id, "dispatch.result", {"ok": dr.ok, "denied_reason": dr.denied_reason})
            if self.telemetry is not None:
                try:
                    self.telemetry.record_latency("dispatch_latency_ms", (time.time() - t_disp0) * 1000.0, tags={"ok": dr.ok})
                except Exception:
                    pass

            if not dr.ok:
                if dr.denied_reason == "confirmation_required" and dr.pending_confirmation:
                    # store pending; require user confirm/cancel
                    expires = float(dr.pending_confirmation.get("expires_seconds") or 15)
                    pending = dict(dr.pending_confirmation)
                    pending["expires_at"] = time.time() + expires
                    self._pending_confirmations[key] = pending
                    return MessageResponse(
                        trace_id=trace_id,
                        reply=str(dr.reply or "Confirmation required."),
                        intent_id=chosen_intent_id,
                        intent_source=router_source,
                        confidence=conf,
                        requires_followup=True,
                        followup_question="Reply 'confirm' to proceed or 'cancel' to abort.",
                        modifications=dict(dr.modifications or {}),
                    )
                return MessageResponse(
                    trace_id=trace_id,
                    reply=dr.reply,
                    intent_id=chosen_intent_id,
                    intent_source=router_source,
                    confidence=conf,
                    requires_followup=False,
                    followup_question=None,
                    modifications=dict(dr.modifications or {}),
                )

            # Always confirm what we're doing (even if execution already simulated).
            reply = confirmation
            if requires_followup and followup_question:
                reply = f"{confirmation} {followup_question}"

            return MessageResponse(
                trace_id=trace_id,
                reply=reply,
                intent_id=chosen_intent_id,
                intent_source=router_source,
                confidence=conf,
                requires_followup=requires_followup,
                followup_question=followup_question,
                modifications=dict(dr.modifications or {}),
            )

