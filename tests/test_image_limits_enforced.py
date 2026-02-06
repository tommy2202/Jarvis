"""
Test: Image generation limits are enforced (fail closed).

Verifies that exceeding max_width, max_height, or max_steps results
in a denial, not a silent clamp.
"""
from __future__ import annotations

import os

import pytest

from jarvis.core.events import EventLogger
from jarvis.core.image_backends.base import BackendHealth, ImageBackend, ImageResult
from jarvis.core.image_backends.models import ImageConfigFile
from jarvis.core.image_handler import ImageHandler


class FakeImageBackend(ImageBackend):
    name = "fake"
    generate_called = False

    def health(self):
        return BackendHealth(ok=True, detail="ok")

    def ensure_ready(self):
        pass

    def is_ready(self):
        return True

    def release(self):
        pass

    def generate(self, **kw):
        self.generate_called = True
        path = os.path.join(kw.get("artifacts_dir", "/tmp"), "test.png")
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as f:
            f.write(b"PNG")
        return ImageResult(output_path=path, width=kw["width"], height=kw["height"], steps=kw["steps"])


def _make_handler(tmp_path, *, max_width=2048, max_height=2048, max_steps=50):
    wf_path = str(tmp_path / "wf.json")
    with open(wf_path, "w") as f:
        f.write('{"1": {"class_type": "KSampler", "inputs": {"steps": 20, "seed": 0}}}')

    config = ImageConfigFile.model_validate({
        "schema_version": 1,
        "backend": {"type": "comfyui_http", "base_url": "http://127.0.0.1:8188", "mode": "external"},
        "limits": {"max_width": max_width, "max_height": max_height, "max_steps": max_steps, "timeout_seconds": 60.0},
        "presets": {"default": {"workflow_template": wf_path, "default_width": 512, "default_height": 512, "default_steps": 10}},
        "security": {"never_log_prompts": True},
        "artifacts_dir": str(tmp_path / "artifacts"),
    })
    backend = FakeImageBackend()
    ev = EventLogger(str(tmp_path / "events.jsonl"))
    handler = ImageHandler(backend=backend, config=config, event_logger=ev)
    return handler, backend


def test_width_exceeded_denied(tmp_path):
    """Width exceeding max_width is denied."""
    handler, backend = _make_handler(tmp_path, max_width=1024)
    result = handler.handle(
        "system.image_generate",
        {"prompt": "test", "width": 2048, "height": 512},
        {"trace_id": "t1"},
    )
    assert result["ok"] is False
    assert "exceeds limit" in result["reply"]
    assert not backend.generate_called


def test_height_exceeded_denied(tmp_path):
    """Height exceeding max_height is denied."""
    handler, backend = _make_handler(tmp_path, max_height=1024)
    result = handler.handle(
        "system.image_generate",
        {"prompt": "test", "width": 512, "height": 2048},
        {"trace_id": "t2"},
    )
    assert result["ok"] is False
    assert "exceeds limit" in result["reply"]
    assert not backend.generate_called


def test_steps_exceeded_denied(tmp_path):
    """Steps exceeding max_steps is denied."""
    handler, backend = _make_handler(tmp_path, max_steps=30)
    result = handler.handle(
        "system.image_generate",
        {"prompt": "test", "steps": 50},
        {"trace_id": "t3"},
    )
    assert result["ok"] is False
    assert "exceeds limit" in result["reply"]
    assert not backend.generate_called


def test_within_limits_allowed(tmp_path):
    """Request within all limits succeeds."""
    handler, backend = _make_handler(tmp_path)
    result = handler.handle(
        "system.image_generate",
        {"prompt": "test", "width": 512, "height": 512, "steps": 10},
        {"trace_id": "t4"},
    )
    assert result["ok"] is True
    assert backend.generate_called


def test_empty_prompt_denied(tmp_path):
    """Empty prompt is denied."""
    handler, backend = _make_handler(tmp_path)
    result = handler.handle(
        "system.image_generate",
        {"prompt": ""},
        {"trace_id": "t5"},
    )
    assert result["ok"] is False
    assert "requires a prompt" in result["reply"]
    assert not backend.generate_called


def test_unknown_preset_denied(tmp_path):
    """Unknown preset is denied."""
    handler, backend = _make_handler(tmp_path)
    result = handler.handle(
        "system.image_generate",
        {"prompt": "test", "preset": "nonexistent"},
        {"trace_id": "t6"},
    )
    assert result["ok"] is False
    assert "Unknown preset" in result["reply"]
    assert not backend.generate_called
