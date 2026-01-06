from __future__ import annotations

from jarvis.core.intent_router import StageAIntent, StageAIntentRouter


def test_stage_a_keyword_match_selects_correct_intent():
    intents = [
        StageAIntent(id="music.play", module_id="music", keywords=["play"], required_args=["song", "service"]),
        StageAIntent(id="other.run", module_id="other", keywords=["other"], required_args=[]),
    ]
    r = StageAIntentRouter(intents, threshold=0.55).route("play Coldplay on spotify")
    assert r.intent_id == "music.play"
    assert r.confidence > 0
    assert r.args.get("song") == "Coldplay"
    assert r.args.get("service") == "Spotify"


def test_stage_a_confidence_threshold_behavior_requires_fallback():
    intents = [StageAIntent(id="music.play", module_id="music", keywords=["play", "music", "spotify"], required_args=[])]
    router = StageAIntentRouter(intents, threshold=0.9)
    r = router.route("play")
    assert r.intent_id == "music.play"
    assert r.confidence < 0.9

