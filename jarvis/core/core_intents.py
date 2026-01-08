from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Tuple, Union

from jarvis.core.text_normalization import normalize_for_matching, tokenize


@dataclass(frozen=True)
class CoreIntent:
    id: str
    label: str
    phrases: List[str]
    is_fact: bool = False


@dataclass(frozen=True)
class MatchResult:
    intent_id: str
    score: float
    matched_phrase: str
    match_type: str  # "exact" | "fuzzy"
    params: Dict[str, Any]


@dataclass(frozen=True)
class AmbiguousMatch:
    candidates: Tuple[MatchResult, MatchResult]
    match_type: str = "fuzzy"


FuzzyOutcome = Union[MatchResult, AmbiguousMatch]


def _jaccard(a: Iterable[str], b: Iterable[str]) -> float:
    aa = set(a)
    bb = set(b)
    if not aa and not bb:
        return 0.0
    return len(aa & bb) / max(1, len(aa | bb))


class CoreIntentRegistry:
    """
    Core intents are deterministic, local, read-only answers.

    This registry intentionally contains only "safe" core intents.
    Modules and LLM are never invoked from this layer.
    """

    def __init__(self, intents: Optional[List[CoreIntent]] = None, *, fuzzy_cfg: Optional[Dict[str, Any]] = None) -> None:
        self._intents = {i.id: i for i in (intents or self._default_intents())}
        self._fuzzy_cfg = dict(fuzzy_cfg or self._default_fuzzy_cfg())

    # -------- registry API (required) --------
    def get_fact_intents(self) -> List[str]:
        return [i.id for i in self._intents.values() if bool(i.is_fact)]

    def get_phrases(self, intent_id: str) -> List[str]:
        i = self._intents.get(intent_id)
        return list(i.phrases) if i else []

    def label(self, intent_id: str) -> str:
        i = self._intents.get(intent_id)
        return str(i.label) if i else intent_id

    def exact_match(self, user_text: str) -> Optional[MatchResult]:
        """
        Exact phrase match for any registered core intent (normalized equality).
        """
        norm = normalize_for_matching(user_text)
        if not norm:
            return None
        matches: List[MatchResult] = []
        for intent in self._intents.values():
            for phrase in intent.phrases:
                if norm == normalize_for_matching(phrase):
                    matches.append(MatchResult(intent_id=intent.id, score=1.0, matched_phrase=phrase, match_type="exact", params={}))
        # If multiple intents share an exact phrase, do not guess; let fuzzy/clarify handle it.
        if len(matches) == 1:
            return matches[0]
        return None

    def fuzzy_match_fact_intent(self, user_text: str) -> Optional[FuzzyOutcome]:
        """
        Fuzzy match for "core facts" only. Deterministic + standard library only.
        Returns:
          - MatchResult (single confident match), or
          - AmbiguousMatch (top-2 within ambiguity margin), or
          - None (no match)
        """
        cfg = self._fuzzy_cfg
        if not bool(cfg.get("enabled", True)):
            return None

        norm = normalize_for_matching(user_text)
        if not norm:
            return None
        tokens = set(tokenize(norm))
        if not tokens:
            return None

        min_score = float(cfg.get("min_score", 0.72))
        min_score_if_contains = float(cfg.get("min_score_if_contains", 0.62))
        ambiguity_margin = float(cfg.get("ambiguity_margin", 0.05))
        max_phrases_per_intent = int(cfg.get("max_phrases_considered_per_intent", 30))
        max_total = int(cfg.get("max_total_phrase_candidates", 200))

        # Deterministic performance bounds (no unbounded scans).
        total_compared = 0

        best: Optional[MatchResult] = None
        second: Optional[MatchResult] = None

        for intent_id in self.get_fact_intents():
            phrases = self.get_phrases(intent_id)[: max(0, max_phrases_per_intent)]
            for phrase in phrases:
                if total_compared >= max_total:
                    break
                total_compared += 1

                ptoks = set(tokenize(phrase))
                if not ptoks:
                    continue

                score = _jaccard(tokens, ptoks)
                contains = ptoks.issubset(tokens)
                if contains:
                    # Contains heuristic: if the phrase tokens are fully present in the input,
                    # treat it as a strong signal even if the input is long/noisy.
                    # Keep single-token phrases conservative to avoid over-matching.
                    if len(ptoks) >= 2:
                        score = max(float(score), 0.85)
                    else:
                        score = min(1.0, score + 0.10)

                mr = MatchResult(intent_id=intent_id, score=float(score), matched_phrase=phrase, match_type="fuzzy", params={})
                if best is None or mr.score > best.score:
                    second = best
                    best = mr
                elif second is None or mr.score > second.score:
                    second = mr

            if total_compared >= max_total:
                break

        if best is None:
            return None

        # Gate by threshold (use lower threshold only if "contains" was true after bump).
        best_phrase_tokens = set(tokenize(best.matched_phrase))
        best_contains = bool(best_phrase_tokens) and best_phrase_tokens.issubset(tokens)
        threshold = min_score_if_contains if best_contains else min_score
        if best.score < threshold:
            return None

        if second is not None and second.intent_id != best.intent_id and abs(best.score - second.score) <= ambiguity_margin:
            return AmbiguousMatch(candidates=(best, second))

        return best

    # -------- defaults --------
    @staticmethod
    def _default_fuzzy_cfg() -> Dict[str, Any]:
        return {
            "enabled": True,
            "min_score": 0.72,
            "min_score_if_contains": 0.62,
            "ambiguity_margin": 0.05,
            "max_phrases_considered_per_intent": 30,
            "max_total_phrase_candidates": 200,
        }

    @staticmethod
    def _default_intents() -> List[CoreIntent]:
        # NOTE: Keep phrases short + stable; fuzzy matching handles variance.
        return [
            CoreIntent(
                id="core.time.now",
                label="time",
                is_fact=True,
                phrases=[
                    "time",
                    "what time is it",
                    "current time",
                    "tell me the time",
                    "time now",
                    "what is it today",
                ],
            ),
            CoreIntent(
                id="core.date.today",
                label="date",
                is_fact=True,
                phrases=[
                    "date",
                    "what date is it",
                    "what day is today",
                    "today's date",
                    "date today",
                    "what is it today",
                ],
            ),
            CoreIntent(
                id="core.status.listening",
                label="listening status",
                is_fact=True,
                phrases=[
                    "are you listening",
                    "listening",
                    "are you there",
                ],
            ),
            CoreIntent(
                id="core.status.admin",
                label="admin status",
                is_fact=True,
                phrases=[
                    "admin status",
                    "are you admin",
                    "are you in admin mode",
                    "is admin unlocked",
                ],
            ),
            CoreIntent(
                id="core.status.busy",
                label="busy status",
                is_fact=True,
                phrases=[
                    "are you busy",
                    "busy",
                    "are you occupied",
                ],
            ),
            CoreIntent(
                id="core.status.health",
                label="health status",
                is_fact=True,
                phrases=[
                    "health",
                    "system health",
                    "are you healthy",
                    "status health",
                ],
            ),
            CoreIntent(
                id="core.identity.version",
                label="version",
                is_fact=True,
                phrases=[
                    "version",
                    "jarvis version",
                    "what version are you",
                ],
            ),
        ]

