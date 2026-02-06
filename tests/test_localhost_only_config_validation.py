"""
Test: Localhost-only config validation for image backend.

Verifies that base_url must be localhost (127.0.0.1 / ::1 / localhost).
Non-localhost URLs must fail config validation at startup.
"""
from __future__ import annotations

import pytest
from pydantic import ValidationError

from jarvis.core.image_backends.models import ImageBackendConfig, ImageConfigFile


# ---------------------------------------------------------------------------
# Allowed URLs (should pass)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("url", [
    "http://127.0.0.1:8188",
    "http://localhost:8188",
    "http://[::1]:8188",
    "http://127.0.0.1:9000",
    "http://localhost:80",
])
def test_localhost_urls_allowed(url):
    """Localhost URLs should pass validation."""
    cfg = ImageBackendConfig(base_url=url)
    assert cfg.base_url == url


# ---------------------------------------------------------------------------
# Disallowed URLs (should fail)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("url", [
    "http://192.168.0.2:8188",
    "http://10.0.0.1:8188",
    "http://example.com:8188",
    "http://0.0.0.0:8188",
    "http://comfyui-server:8188",
])
def test_non_localhost_urls_rejected(url):
    """Non-localhost URLs must fail validation."""
    with pytest.raises(ValidationError, match="localhost"):
        ImageBackendConfig(base_url=url)


def test_full_config_rejects_remote_url():
    """Full ImageConfigFile rejects non-localhost backend URL."""
    with pytest.raises(ValidationError):
        ImageConfigFile.model_validate({
            "schema_version": 1,
            "backend": {
                "type": "comfyui_http",
                "base_url": "http://192.168.0.2:8188",
                "mode": "external",
            },
        })


def test_full_config_accepts_localhost():
    """Full ImageConfigFile accepts localhost."""
    cfg = ImageConfigFile.model_validate({
        "schema_version": 1,
        "backend": {
            "type": "comfyui_http",
            "base_url": "http://127.0.0.1:8188",
            "mode": "external",
        },
    })
    assert cfg.backend.base_url == "http://127.0.0.1:8188"


def test_schema_version_required():
    """schema_version must be present and >= 1."""
    cfg = ImageConfigFile.model_validate({"schema_version": 1})
    assert cfg.schema_version == 1


def test_schema_version_zero_rejected():
    """schema_version=0 should fail validation."""
    with pytest.raises(ValidationError):
        ImageConfigFile.model_validate({"schema_version": 0})
