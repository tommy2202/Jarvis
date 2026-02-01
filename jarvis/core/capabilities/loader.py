from __future__ import annotations

from typing import Any, Dict

from pydantic import ValidationError

from jarvis.core.capabilities.defaults import default_capabilities
from jarvis.core.capabilities.models import CAPABILITIES_SCHEMA_VERSION, CapabilitiesConfig, CapabilityDefinition


class CapabilityConfigError(RuntimeError):
    pass


def default_config_dict() -> Dict[str, Any]:
    caps = default_capabilities()
    return {
        "schema_version": CAPABILITIES_SCHEMA_VERSION,
        "capabilities": {k: v.model_dump() for k, v in caps.items()},
        "intent_requirements": {
            "music.play": ["CAP_AUDIO_OUTPUT"],
            "anime_dubbing.run": ["CAP_HEAVY_COMPUTE", "CAP_RUN_SUBPROCESS", "CAP_WRITE_FILES"],
            "system.job.submit": [],
            "system.tool.call": [],
        },
        "source_policies": {
            "voice": {"deny": ["CAP_ADMIN_ACTION"], "require_admin_for": [], "allow_all_non_sensitive": False},
            "web": {"deny": ["CAP_ADMIN_ACTION"], "require_admin_for": ["CAP_HEAVY_COMPUTE"], "allow_all_non_sensitive": False},
            "cli": {"deny": [], "require_admin_for": [], "allow_all_non_sensitive": True},
            "ui": {"deny": [], "require_admin_for": [], "allow_all_non_sensitive": True},
            "system": {"deny": [], "require_admin_for": [], "allow_all_non_sensitive": True},
        },
        "safe_mode": {"deny": ["CAP_NETWORK_ACCESS", "CAP_RUN_SUBPROCESS", "CAP_HEAVY_COMPUTE"]},
        "heavy_compute_whitelist_intents": [],
    }


def validate_and_normalize(raw: Dict[str, Any]) -> CapabilitiesConfig:
    if not isinstance(raw, dict):
        raise CapabilityConfigError("capabilities.json must be an object.")
    if "schema_version" not in raw:
        raise CapabilityConfigError("capabilities.json missing schema_version.")
    try:
        schema_version = int(raw.get("schema_version"))
    except Exception as e:  # noqa: BLE001
        raise CapabilityConfigError("capabilities.json schema_version must be an integer.") from e
    if schema_version != CAPABILITIES_SCHEMA_VERSION:
        raise CapabilityConfigError(
            f"capabilities.json schema_version mismatch (expected {CAPABILITIES_SCHEMA_VERSION})."
        )
    try:
        cfg = CapabilitiesConfig.model_validate(raw)
    except ValidationError as e:
        raise CapabilityConfigError(str(e)) from e

    # Validate that keys match ids
    for k, v in cfg.capabilities.items():
        if k != v.id:
            raise CapabilityConfigError(f"Capability key '{k}' must match definition id '{v.id}'.")

    # Validate intent requirements refer to known caps
    cap_ids = set(cfg.capabilities.keys())
    for intent_id, reqs in cfg.intent_requirements.items():
        for cap in reqs:
            if cap not in cap_ids:
                raise CapabilityConfigError(f"Intent '{intent_id}' references unknown capability '{cap}'.")

    # Validate policies refer to known caps
    for src, pol in cfg.source_policies.items():
        for cap in (pol.deny or []) + (pol.require_admin_for or []):
            if cap not in cap_ids:
                raise CapabilityConfigError(f"source_policies[{src}] references unknown capability '{cap}'.")

    for cap in cfg.safe_mode.deny or []:
        if cap not in cap_ids:
            raise CapabilityConfigError(f"safe_mode.deny references unknown capability '{cap}'.")

    return cfg

