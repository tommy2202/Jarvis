from __future__ import annotations

from typing import Any, Dict


MODULE_META = {
    "id": "music",
    "name": "Music",
    "description": "Simulated music playback (no external APIs).",
    "default_intent": "music.play",
    "required_args": ["song", "service"],
    "resource_intensive": False,
    # Contract metadata (enforced by dispatcher)
    "resource_class": "default",
    "execution_mode": "inline",
    "required_capabilities": ["CAP_AUDIO_OUTPUT"],
}


def handle(intent_id: str, args: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
    # Simulation only — no network, no shell, no external side-effects.
    if intent_id != "music.play":
        return {"ok": False, "error": "unsupported intent"}
    song = args.get("song") or "music"
    service = args.get("service") or "default player"
    return {"ok": True, "action": "play", "song": song, "service": service}

