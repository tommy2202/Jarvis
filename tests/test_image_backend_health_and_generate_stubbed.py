"""
Test: ComfyUI image backend health check and generate flow (stubbed HTTP).

Uses monkeypatched requests to simulate ComfyUI endpoints.
No real ComfyUI server needed.
"""
from __future__ import annotations

import json
import os
from typing import Any, Dict
from unittest.mock import MagicMock, patch

import pytest
import requests

from jarvis.core.image_backends.comfyui import ComfyUIBackend, _inject_params
from jarvis.core.image_backends.base import BackendHealth, ImageResult


# ---------------------------------------------------------------------------
# Stub HTTP responses
# ---------------------------------------------------------------------------


class StubResponse:
    def __init__(self, status_code: int = 200, json_data: Any = None, content: bytes = b""):
        self.status_code = status_code
        self._json_data = json_data
        self.content = content

    def json(self):
        return self._json_data

    def raise_for_status(self):
        if self.status_code >= 400:
            raise requests.HTTPError(f"HTTP {self.status_code}")


FAKE_PROMPT_ID = "abc-123-fake"
FAKE_SYSTEM_STATS = {"system": {"os": "linux"}}


def _make_history_response(prompt_id: str) -> Dict[str, Any]:
    return {
        prompt_id: {
            "outputs": {
                "7": {
                    "images": [
                        {
                            "filename": "jarvis_00001_.png",
                            "subfolder": "",
                            "type": "output",
                        }
                    ]
                }
            }
        }
    }


# 8x8 minimal PNG (valid PNG header + IHDR + IDAT + IEND)
MINIMAL_PNG = (
    b"\x89PNG\r\n\x1a\n"
    b"\x00\x00\x00\rIHDR\x00\x00\x00\x08\x00\x00\x00\x08\x08\x02"
    b"\x00\x00\x00Km)\x9b\x00\x00\x00\x15IDATx\x9cc\xf8\x0f\x00"
    b"\x01\x01\x00\x05\x18\xd8N\x00\x08\x00\x01\t\xa6\xa8\xa0\x00"
    b"\x00\x00\x00IEND\xaeB`\x82"
)


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_health_ok(monkeypatch):
    """Health check succeeds when /system_stats returns 200."""
    backend = ComfyUIBackend(base_url="http://127.0.0.1:8188")

    def fake_get(url, **kw):
        if "/system_stats" in url:
            return StubResponse(200, json_data=FAKE_SYSTEM_STATS)
        return StubResponse(404)

    monkeypatch.setattr(requests, "get", fake_get)
    h = backend.health()
    assert h.ok is True
    assert h.detail == "ok"


def test_health_fail(monkeypatch):
    """Health check fails when /system_stats is unreachable."""
    backend = ComfyUIBackend(base_url="http://127.0.0.1:8188")

    def fake_get(url, **kw):
        raise ConnectionError("refused")

    monkeypatch.setattr(requests, "get", fake_get)
    h = backend.health()
    assert h.ok is False


def test_generate_stubbed(monkeypatch, tmp_path):
    """Full generate flow: submit -> poll -> download -> save."""
    backend = ComfyUIBackend(base_url="http://127.0.0.1:8188")
    artifacts_dir = str(tmp_path / "images")

    call_log = []

    def fake_post(url, **kw):
        call_log.append(("POST", url))
        if "/prompt" in url:
            return StubResponse(200, json_data={"prompt_id": FAKE_PROMPT_ID})
        return StubResponse(404)

    def fake_get(url, **kw):
        call_log.append(("GET", url))
        if f"/history/{FAKE_PROMPT_ID}" in url:
            return StubResponse(200, json_data=_make_history_response(FAKE_PROMPT_ID))
        if "/view" in url:
            return StubResponse(200, content=MINIMAL_PNG)
        if "/system_stats" in url:
            return StubResponse(200, json_data=FAKE_SYSTEM_STATS)
        return StubResponse(404)

    monkeypatch.setattr(requests, "post", fake_post)
    monkeypatch.setattr(requests, "get", fake_get)

    # Minimal workflow
    workflow = {
        "1": {"class_type": "CheckpointLoaderSimple", "inputs": {"ckpt_name": "test.safetensors"}},
        "2": {"class_type": "CLIPTextEncode", "inputs": {"text": "", "clip": ["1", 1]}},
        "3": {"class_type": "EmptyLatentImage", "inputs": {"width": 512, "height": 512, "batch_size": 1}},
        "4": {"class_type": "KSampler", "inputs": {"steps": 10, "seed": 0, "model": ["1", 0]}},
    }

    result = backend.generate(
        prompt="a test image",
        preset="default",
        width=1024,
        height=1024,
        steps=20,
        seed=42,
        negative_prompt="bad quality",
        trace_id="test-trace",
        timeout_seconds=30.0,
        workflow_json=workflow,
        artifacts_dir=artifacts_dir,
    )

    assert isinstance(result, ImageResult)
    assert result.output_path.endswith(".png")
    assert os.path.isfile(result.output_path)
    assert result.width == 1024
    assert result.height == 1024
    assert result.steps == 20
    assert result.seed == 42
    assert result.preset == "default"

    # Verify file content is our minimal PNG
    with open(result.output_path, "rb") as f:
        content = f.read()
    assert content == MINIMAL_PNG


def test_generate_timeout(monkeypatch):
    """Generate times out if ComfyUI never completes."""
    backend = ComfyUIBackend(base_url="http://127.0.0.1:8188")

    def fake_post(url, **kw):
        if "/prompt" in url:
            return StubResponse(200, json_data={"prompt_id": "never-done"})
        return StubResponse(404)

    def fake_get(url, **kw):
        # Always return empty history (never completes)
        if "/history/" in url:
            return StubResponse(200, json_data={})
        return StubResponse(404)

    monkeypatch.setattr(requests, "post", fake_post)
    monkeypatch.setattr(requests, "get", fake_get)

    with pytest.raises(requests.Timeout):
        backend.generate(
            prompt="test",
            preset="default",
            width=512,
            height=512,
            steps=10,
            trace_id="t",
            timeout_seconds=2.0,
            workflow_json={"1": {"class_type": "KSampler", "inputs": {"steps": 10}}},
            artifacts_dir="/tmp/test",
        )


# ---------------------------------------------------------------------------
# Workflow injection tests
# ---------------------------------------------------------------------------


def test_inject_params_positive_prompt():
    """Positive prompt injected into CLIPTextEncode nodes."""
    wf = {
        "1": {"class_type": "CLIPTextEncode", "inputs": {"text": "", "clip": []}},
        "2": {"class_type": "CLIPTextEncode", "inputs": {"text": "", "clip": [], "_role": "negative"}},
    }
    result = _inject_params(wf, prompt="hello", negative_prompt="bad", width=512, height=512, steps=10, seed=None)
    assert result["1"]["inputs"]["text"] == "hello"
    assert result["2"]["inputs"]["text"] == "bad"


def test_inject_params_dimensions_and_steps():
    """Width/height/steps/seed injected into correct node types."""
    wf = {
        "1": {"class_type": "EmptyLatentImage", "inputs": {"width": 0, "height": 0, "batch_size": 1}},
        "2": {"class_type": "KSampler", "inputs": {"steps": 0, "seed": 0}},
    }
    result = _inject_params(wf, prompt="x", negative_prompt="", width=768, height=768, steps=30, seed=99)
    assert result["1"]["inputs"]["width"] == 768
    assert result["1"]["inputs"]["height"] == 768
    assert result["2"]["inputs"]["steps"] == 30
    assert result["2"]["inputs"]["seed"] == 99
