from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Dict, Optional

from pydantic import BaseModel, Field, ValidationError

from jarvis.core.llm_contracts import LLMRequest, LLMRole, Message, OutputSchema


class LLMOutput(BaseModel):
    # Back-compat for older callers/tests; maps to intent_fallback output schema.
    intent: str
    confidence: float = Field(ge=0.0, le=1.0)
    args: Dict[str, Any] = Field(default_factory=dict)
    confirmation_text: str
    requires_admin: bool = False


@dataclass(frozen=True)
class LLMConfig:
    # Legacy config retained for tests; lifecycle config is in config/llm.json.
    mock_mode: bool = True


class StageBLLMRouter:
    """
    Stage-B router that uses the LLM lifecycle controller + strict JSON contracts.
    If no lifecycle provided, it can operate in safe mock mode only.
    """

    def __init__(self, cfg: LLMConfig, lifecycle=None):
        self.cfg = cfg
        self.lifecycle = lifecycle

    def warmup(self) -> None:
        if self.lifecycle is None:
            return
        try:
            self.lifecycle.ensure_role_ready("chat", trace_id="llm")
        except Exception:
            return

    def unload(self) -> None:
        if self.lifecycle is None:
            return
        try:
            self.lifecycle.unload_role("chat", reason="idle", trace_id="llm")
        except Exception:
            return

    def route(self, user_text: str, allowed_intents: Dict[str, Dict[str, Any]]) -> Optional[LLMOutput]:
        if self.lifecycle is None:
            if not self.cfg.mock_mode:
                return None
            return LLMOutput(intent="unknown", confidence=0.0, args={}, confirmation_text="I’m not sure what you want me to do.", requires_admin=False)

        allowed = sorted([k for k in allowed_intents.keys() if k != "unknown"])
        req = LLMRequest(
            trace_id="llm",
            role=LLMRole.chat,
            messages=[Message(role="user", content=user_text)],
            output_schema=OutputSchema.intent_fallback,
            safety={"allowed_intents": allowed, "denylist_phrases": ["ignore previous instructions", "system prompt", "reveal secrets"]},
            max_tokens=512,
            temperature=0.0,
        )
        resp = self.lifecycle.call("chat", req)
        if resp.status.value != "ok" or not resp.parsed_json:
            if self.cfg.mock_mode:
                return LLMOutput(intent="unknown", confidence=0.0, args={}, confirmation_text="I’m not sure what you want me to do.", requires_admin=False)
            return None

        try:
            # Map contract -> legacy output
            out = LLMOutput(
                intent=str(resp.parsed_json.get("intent_id") or "unknown"),
                confidence=float(resp.parsed_json.get("confidence") or 0.0),
                args=dict(resp.parsed_json.get("args") or {}),
                confirmation_text=str(resp.parsed_json.get("confirmation_text") or ""),
                requires_admin=bool(resp.parsed_json.get("requires_admin") or False),
            )
            return out
        except Exception:
            return None

