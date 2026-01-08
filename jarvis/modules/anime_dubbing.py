from __future__ import annotations

from typing import Any, Dict


MODULE_META = {
    "id": "anime_dubbing",
    "name": "Anime Dubbing",
    "description": "Admin-only: placeholder for future dubbing pipeline.",
    "default_intent": "anime_dubbing.run",
    "required_args": [],
    # Mark as resource intensive to force admin-only (fail-safe).
    "resource_intensive": True,
    # Contract metadata (enforced by dispatcher)
    "resource_class": "local",
    "execution_mode": "inline",
    "capabilities_by_intent": {
        "anime_dubbing.run": ["CAP_HEAVY_COMPUTE", "CAP_RUN_SUBPROCESS", "CAP_WRITE_FILES"],
    },
}


def handle(intent_id: str, args: Dict[str, Any], context: Dict[str, Any]) -> Dict[str, Any]:
    if intent_id != "anime_dubbing.run":
        return {"ok": False, "error": "unsupported intent"}
    # Still simulated; dispatcher will deny if not admin.
    return {"ok": True, "action": "dubbing_start_simulated"}

