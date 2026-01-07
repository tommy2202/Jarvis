from __future__ import annotations

from jarvis.core.capabilities.models import CapabilityDefinition, CapabilitySensitivity, DefaultPolicy


def default_capabilities() -> dict[str, CapabilityDefinition]:
    """
    Default capability set. These are core-only and validated.
    """
    caps = {
        "CAP_READ_FILES": CapabilityDefinition(
            id="CAP_READ_FILES",
            description="Read local files (non-secret).",
            default_policy=DefaultPolicy.allow,
            sensitivity=CapabilitySensitivity.normal,
            requires_admin=False,
            audit=False,
        ),
        "CAP_WRITE_FILES": CapabilityDefinition(
            id="CAP_WRITE_FILES",
            description="Write local files.",
            default_policy=DefaultPolicy.deny,
            sensitivity=CapabilitySensitivity.normal,
            requires_admin=False,
            audit=True,
        ),
        "CAP_NETWORK_ACCESS": CapabilityDefinition(
            id="CAP_NETWORK_ACCESS",
            description="Perform outbound network access.",
            default_policy=DefaultPolicy.deny,
            sensitivity=CapabilitySensitivity.high,
            requires_admin=True,
            audit=True,
        ),
        "CAP_RUN_SUBPROCESS": CapabilityDefinition(
            id="CAP_RUN_SUBPROCESS",
            description="Run a local subprocess (not arbitrary shell by default).",
            default_policy=DefaultPolicy.deny,
            sensitivity=CapabilitySensitivity.high,
            requires_admin=True,
            audit=True,
        ),
        "CAP_HEAVY_COMPUTE": CapabilityDefinition(
            id="CAP_HEAVY_COMPUTE",
            description="Perform heavy compute (GPU/CPU intensive).",
            default_policy=DefaultPolicy.deny,
            sensitivity=CapabilitySensitivity.high,
            requires_admin=True,
            audit=True,
        ),
        "CAP_IMAGE_GENERATION": CapabilityDefinition(
            id="CAP_IMAGE_GENERATION",
            description="Generate images (high-risk).",
            default_policy=DefaultPolicy.deny,
            sensitivity=CapabilitySensitivity.high,
            requires_admin=True,
            audit=True,
        ),
        "CAP_CODE_GENERATION": CapabilityDefinition(
            id="CAP_CODE_GENERATION",
            description="Generate code (high-risk).",
            default_policy=DefaultPolicy.deny,
            sensitivity=CapabilitySensitivity.high,
            requires_admin=True,
            audit=True,
        ),
        "CAP_AUDIO_INPUT": CapabilityDefinition(
            id="CAP_AUDIO_INPUT",
            description="Use microphone / audio input.",
            default_policy=DefaultPolicy.allow,
            sensitivity=CapabilitySensitivity.normal,
            requires_admin=False,
            audit=False,
        ),
        "CAP_AUDIO_OUTPUT": CapabilityDefinition(
            id="CAP_AUDIO_OUTPUT",
            description="Play audio output (TTS/beeps).",
            default_policy=DefaultPolicy.allow,
            sensitivity=CapabilitySensitivity.normal,
            requires_admin=False,
            audit=False,
        ),
        "CAP_DEVICE_CONTROL": CapabilityDefinition(
            id="CAP_DEVICE_CONTROL",
            description="Control devices/OS settings (high-risk).",
            default_policy=DefaultPolicy.deny,
            sensitivity=CapabilitySensitivity.high,
            requires_admin=True,
            audit=True,
        ),
        "CAP_ADMIN_ACTION": CapabilityDefinition(
            id="CAP_ADMIN_ACTION",
            description="Perform admin-gated operations.",
            default_policy=DefaultPolicy.deny,
            sensitivity=CapabilitySensitivity.high,
            requires_admin=True,
            audit=True,
            requires_secrets=True,
        ),
    }
    return caps


# Hard-coded admin-only caps (non-negotiable)
ADMIN_ONLY_CAPS = {"CAP_ADMIN_ACTION", "CAP_IMAGE_GENERATION", "CAP_CODE_GENERATION"}

