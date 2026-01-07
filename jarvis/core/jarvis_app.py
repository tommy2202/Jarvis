from __future__ import annotations

import threading
import time
import uuid
from dataclasses import dataclass
from typing import Any, Dict, Optional

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
        self._lock = threading.Lock()

    def _render_confirmation(self, intent_id: str, args: Dict[str, Any]) -> str:
        tmpl = self.confirmation_templates.get(intent_id) or "Okay."
        try:
            return tmpl.format(**args)
        except Exception:  # noqa: BLE001
            return tmpl

    def _required_missing(self, intent_id: str, args: Dict[str, Any]) -> bool:
        cfg = self.intent_config_by_id.get(intent_id) or {}
        required = cfg.get("required_args") or []
        return any((r not in args or args.get(r) in (None, "")) for r in required)

    def process_message(self, message: str, client: Optional[Dict[str, Any]] = None, *, source: str = "cli", safe_mode: bool = False, shutting_down: bool = False) -> MessageResponse:
        with self._lock:
            trace_id = uuid.uuid4().hex
            self.event_logger.log(trace_id, "request.received", {"message": message, "client": client or {}})

            # Stage A
            t_route0 = time.time()
            a: IntentResult = self.stage_a.route(message)
            self.event_logger.log(trace_id, "router.stage_a", a.model_dump())

            chosen_intent_id: Optional[str] = a.intent_id
            chosen_args: Dict[str, Any] = dict(a.args or {})
            source = "stage_a"
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
                    source = "stage_b"
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
                        self.telemetry.record_latency("routing_latency_ms", (time.time() - t_route0) * 1000.0, tags={"source": source})
                    except Exception:
                        pass
                return MessageResponse(
                    trace_id=trace_id,
                    reply="I can’t execute unknown intents.",
                    intent_id="unknown",
                    intent_source=source,
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
            dispatch_context = {"client": client or {}, "source": source, "safe_mode": bool(safe_mode), "shutting_down": bool(shutting_down)}
            if self.telemetry is not None:
                try:
                    self.telemetry.record_latency("routing_latency_ms", (time.time() - t_route0) * 1000.0, tags={"source": source})
                except Exception:
                    pass
            t_disp0 = time.time()
            dr = self.dispatcher.dispatch(trace_id, chosen_intent_id, module_id, chosen_args, dispatch_context)
            self.event_logger.log(trace_id, "dispatch.result", {"ok": dr.ok, "denied_reason": dr.denied_reason})
            if self.telemetry is not None:
                try:
                    self.telemetry.record_latency("dispatch_latency_ms", (time.time() - t_disp0) * 1000.0, tags={"ok": dr.ok})
                except Exception:
                    pass

            if not dr.ok:
                return MessageResponse(
                    trace_id=trace_id,
                    reply=dr.reply,
                    intent_id=chosen_intent_id,
                    intent_source=source,
                    confidence=conf,
                    requires_followup=False,
                    followup_question=None,
                )

            # Always confirm what we're doing (even if execution already simulated).
            reply = confirmation
            if requires_followup and followup_question:
                reply = f"{confirmation} {followup_question}"

            return MessageResponse(
                trace_id=trace_id,
                reply=reply,
                intent_id=chosen_intent_id,
                intent_source=source,
                confidence=conf,
                requires_followup=requires_followup,
                followup_question=followup_question,
            )

