from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

from pydantic import BaseModel, Field


class IntentResult(BaseModel):
    intent_id: Optional[str] = None
    confidence: float = 0.0
    args: Dict[str, Any] = Field(default_factory=dict)
    reason: str = ""
    source: str = "stage_a"  # stage_a|stage_b


@dataclass(frozen=True)
class StageAIntent:
    id: str
    module_id: str
    keywords: List[str]
    required_args: List[str]


class StageAIntentRouter:
    def __init__(self, intents: List[StageAIntent], threshold: float = 0.55):
        self.intents = intents
        self.threshold = threshold

    @staticmethod
    def _tokenize(text: str) -> List[str]:
        return re.findall(r"[a-z0-9']+", text.lower())

    def _score(self, tokens: List[str], intent: StageAIntent) -> Tuple[float, List[str]]:
        if not intent.keywords:
            return 0.0, []
        kw = [k.lower() for k in intent.keywords]
        hits = [k for k in kw if k in tokens]
        confidence = len(hits) / max(1, len(kw))
        return confidence, hits

    def _extract_basic_args(self, intent_id: str, text: str) -> Dict[str, Any]:
        # Minimal extraction for example "music.play"
        t = text.strip()
        out: Dict[str, Any] = {}
        if intent_id == "music.play":
            # service: "on spotify|youtube|apple"
            m = re.search(r"\bon\s+(spotify|youtube|apple|amazon)\b", t, re.IGNORECASE)
            if m:
                svc = m.group(1).lower()
                canonical = {"spotify": "Spotify", "youtube": "YouTube", "apple": "Apple Music", "amazon": "Amazon Music"}
                out["service"] = canonical.get(svc, svc)
            # song: try "play <song>" or "play <song> on <service>"
            m2 = re.search(r"\bplay\s+(.+?)(?:\s+on\s+(?:spotify|youtube|apple|amazon)\b|$)", t, re.IGNORECASE)
            if m2:
                song = m2.group(1).strip().strip("\"'")
                if song and song.lower() not in {"music", "a song"}:
                    out["song"] = song
        return out

    def route(self, text: str) -> IntentResult:
        tokens = self._tokenize(text)
        best: Optional[StageAIntent] = None
        best_conf = 0.0
        best_hits: List[str] = []

        for intent in self.intents:
            conf, hits = self._score(tokens, intent)
            if conf > best_conf:
                best_conf, best_hits, best = conf, hits, intent

        if not best or best_conf <= 0.0:
            return IntentResult(intent_id=None, confidence=0.0, args={}, reason="No keyword matches.", source="stage_a")

        args = self._extract_basic_args(best.id, text)
        return IntentResult(
            intent_id=best.id,
            confidence=float(best_conf),
            args=args,
            reason=f"Matched keywords: {best_hits}",
            source="stage_a",
        )

