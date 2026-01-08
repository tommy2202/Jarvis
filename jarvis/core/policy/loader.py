from __future__ import annotations

from typing import Any, Dict, Tuple

from pydantic import ValidationError

from jarvis.core.policy.models import PolicyConfigFile


def load_policy_config(config_manager) -> Tuple[PolicyConfigFile, bool, str]:
    """
    Returns (cfg, failsafe, error_message).
    If validation fails, returns a disabled/empty config and failsafe=True.
    """
    try:
        raw: Dict[str, Any] = config_manager.read_non_sensitive("policy.json")
        cfg = PolicyConfigFile.model_validate(raw or {})
        return cfg, False, ""
    except Exception as e:
        # fail-safe: treat as disabled but engine will enforce conservative defaults
        return PolicyConfigFile(enabled=False), True, str(e)

