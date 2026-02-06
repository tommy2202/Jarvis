"""Pydantic request / config models for the image generation subsystem."""
from __future__ import annotations

import ipaddress
import urllib.parse
from typing import Any, Dict, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator


# ---------------------------------------------------------------------------
# Config models
# ---------------------------------------------------------------------------

class ImageBackendConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    type: str = "comfyui_http"
    base_url: str = "http://127.0.0.1:8188"
    mode: str = "external"

    @field_validator("base_url")
    @classmethod
    def _localhost_only(cls, v: str) -> str:
        """Enforce localhost-only base_url at config validation time."""
        parsed = urllib.parse.urlparse(v)
        host = (parsed.hostname or "").lower()
        allowed = {"127.0.0.1", "::1", "localhost"}
        if host not in allowed:
            try:
                addr = ipaddress.ip_address(host)
                if not addr.is_loopback:
                    raise ValueError(
                        f"Image backend base_url must be localhost, got '{host}'. "
                        f"Remote backends are not allowed."
                    )
            except ValueError:
                if host not in allowed:
                    raise ValueError(
                        f"Image backend base_url must be localhost, got '{host}'. "
                        f"Remote backends are not allowed."
                    )
        return v


class ImageLimitsConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    max_width: int = Field(default=2048, ge=64, le=8192)
    max_height: int = Field(default=2048, ge=64, le=8192)
    max_steps: int = Field(default=50, ge=1, le=200)
    timeout_seconds: float = Field(default=300.0, ge=10.0, le=3600.0)


class ImagePresetConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    workflow_template: str = "config/workflows/default_sdxl.json"
    default_width: int = Field(default=1024, ge=64, le=8192)
    default_height: int = Field(default=1024, ge=64, le=8192)
    default_steps: int = Field(default=20, ge=1, le=200)
    default_negative_prompt: str = ""


class ImageSecurityConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    never_log_prompts: bool = True


class ImageConfigFile(BaseModel):
    """Top-level image.json config (validated at startup)."""
    model_config = ConfigDict(extra="forbid")
    schema_version: int = Field(default=1, ge=1, le=10)
    enabled: bool = True
    backend: ImageBackendConfig = Field(default_factory=ImageBackendConfig)
    limits: ImageLimitsConfig = Field(default_factory=ImageLimitsConfig)
    presets: Dict[str, ImagePresetConfig] = Field(
        default_factory=lambda: {"default": ImagePresetConfig()}
    )
    security: ImageSecurityConfig = Field(default_factory=ImageSecurityConfig)
    artifacts_dir: str = "artifacts/images"
