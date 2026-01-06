from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Dict, Optional

import requests
from pydantic import BaseModel, Field, ValidationError


class LLMOutput(BaseModel):
    intent: str
    confidence: float = Field(ge=0.0, le=1.0)
    args: Dict[str, Any] = Field(default_factory=dict)
    confirmation_text: str
    requires_admin: bool = False


@dataclass(frozen=True)
class LLMConfig:
    base_url: str = "http://localhost:11434"
    timeout_seconds: float = 5.0
    model: str = "qwen:14b-chat"
    mock_mode: bool = True


class StageBLLMRouter:
    """
    Local HTTP LLM interface with safe mock fallback.
    Expects OpenAI-compatible /v1/chat/completions OR falls back to mock.

    The model must output strict JSON with the LLMOutput schema.
    """

    def __init__(self, cfg: LLMConfig):
        self.cfg = cfg
        self._conversation_active = False

    def warmup(self) -> None:
        """
        Called when a voice wake happens.
        For a remote/local HTTP server this is a best-effort ping; safe if server absent.
        """
        self._conversation_active = True
        try:
            # Ollama supports /api/tags; many servers don't. This is best-effort only.
            url = f"{self.cfg.base_url.rstrip('/')}/api/tags"
            requests.get(url, timeout=min(self.cfg.timeout_seconds, 2.0))
        except Exception:
            return

    def unload(self) -> None:
        """
        Called when voice returns to idle sleep.
        For an HTTP client, we just drop any client-side state.
        """
        self._conversation_active = False

    def _prompt(self, user_text: str, allowed_intents: Dict[str, Dict[str, Any]]) -> str:
        # Keep prompt minimal but strict: produce JSON ONLY.
        intent_list = "\n".join([f"- {k}" for k in sorted(allowed_intents.keys())])
        return (
            "You are an intent router. Output STRICT JSON only, no markdown.\n"
            "Schema: {\"intent\": str, \"confidence\": float, \"args\": object, \"confirmation_text\": str, \"requires_admin\": bool}\n"
            "Rules:\n"
            "- intent MUST be one of the allowed intents listed below.\n"
            "- confidence in [0,1].\n"
            "- If unsure, set intent=\"unknown\" and confidence=0.\n"
            "\n"
            f"Allowed intents:\n{intent_list}\n"
            "\n"
            f"User message: {user_text}\n"
        )

    def _call_openai_compat(self, prompt: str) -> str:
        url = f"{self.cfg.base_url.rstrip('/')}/v1/chat/completions"
        payload = {
            "model": self.cfg.model,
            "messages": [
                {"role": "system", "content": "Return JSON only."},
                {"role": "user", "content": prompt},
            ],
            "temperature": 0.0,
        }
        r = requests.post(url, json=payload, timeout=self.cfg.timeout_seconds)
        r.raise_for_status()
        data = r.json()
        return data["choices"][0]["message"]["content"]

    def route(self, user_text: str, allowed_intents: Dict[str, Dict[str, Any]]) -> Optional[LLMOutput]:
        prompt = self._prompt(user_text, allowed_intents)
        raw: Optional[str] = None
        try:
            raw = self._call_openai_compat(prompt)
        except Exception:  # noqa: BLE001
            if not self.cfg.mock_mode:
                return None
            # Safe mock: refuse unknowns, never invent new intents.
            raw = json.dumps(
                {
                    "intent": "unknown",
                    "confidence": 0.0,
                    "args": {},
                    "confirmation_text": "I’m not sure what you want me to do.",
                    "requires_admin": False,
                }
            )

        try:
            obj = json.loads(raw)
        except Exception:  # noqa: BLE001
            return None

        try:
            out = LLMOutput.model_validate(obj)
        except ValidationError:
            return None

        return out

