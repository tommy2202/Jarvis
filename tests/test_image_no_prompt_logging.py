"""
Test: Image generation prompts never appear in any log/audit files.

Sends a prompt containing "SECRET123" and verifies it does NOT
appear in any event logs.
"""
from __future__ import annotations

import os

import pytest

from jarvis.core.events import EventLogger
from jarvis.core.image_backends.base import BackendHealth, ImageBackend, ImageResult
from jarvis.core.image_backends.models import ImageConfigFile
from jarvis.core.image_handler import ImageHandler


SECRET_MARKER = "SECRET123_IMAGE_NEVER_LOG"


class FakeImageBackend(ImageBackend):
    """Backend that always succeeds without real generation."""

    name = "fake"

    def health(self):
        return BackendHealth(ok=True, detail="ok")

    def ensure_ready(self):
        pass

    def is_ready(self):
        return True

    def release(self):
        pass

    def generate(self, *, prompt, preset, width, height, steps, seed=None,
                 negative_prompt=None, trace_id, timeout_seconds,
                 workflow_json=None, artifacts_dir="artifacts/images"):
        # Write a fake image file
        os.makedirs(artifacts_dir, exist_ok=True)
        path = os.path.join(artifacts_dir, f"{trace_id}_test.png")
        with open(path, "wb") as f:
            f.write(b"\x89PNG_fake")
        return ImageResult(
            output_path=path,
            preset=preset,
            seed=seed,
            width=width,
            height=height,
            steps=steps,
        )


def test_prompt_not_in_event_log(tmp_path):
    """Prompt containing SECRET123 must not appear in event logs."""
    events_path = str(tmp_path / "events.jsonl")
    ev = EventLogger(events_path)
    artifacts_dir = str(tmp_path / "artifacts")

    # Create a minimal workflow template
    wf_path = str(tmp_path / "wf.json")
    with open(wf_path, "w") as f:
        f.write('{"1": {"class_type": "KSampler", "inputs": {"steps": 20, "seed": 0}}}')

    config = ImageConfigFile.model_validate({
        "schema_version": 1,
        "enabled": True,
        "backend": {"type": "comfyui_http", "base_url": "http://127.0.0.1:8188", "mode": "external"},
        "limits": {"max_width": 2048, "max_height": 2048, "max_steps": 50, "timeout_seconds": 60.0},
        "presets": {"default": {"workflow_template": wf_path, "default_width": 1024, "default_height": 1024, "default_steps": 20}},
        "security": {"never_log_prompts": True},
        "artifacts_dir": artifacts_dir,
    })

    handler = ImageHandler(
        backend=FakeImageBackend(),
        config=config,
        event_logger=ev,
    )

    result = handler.handle(
        "system.image_generate",
        {"prompt": f"Draw {SECRET_MARKER} in a beautiful landscape"},
        {"trace_id": "t1"},
    )
    assert result["ok"] is True

    # Read the events log
    assert os.path.exists(events_path), "Event log should exist"
    with open(events_path, "r", encoding="utf-8") as f:
        log_content = f.read()

    assert SECRET_MARKER not in log_content, (
        f"Secret marker '{SECRET_MARKER}' was found in event log! "
        f"Prompts must NEVER be logged."
    )


def test_negative_prompt_not_in_log(tmp_path):
    """Negative prompt with secret marker must not leak to logs."""
    events_path = str(tmp_path / "events.jsonl")
    ev = EventLogger(events_path)
    artifacts_dir = str(tmp_path / "artifacts")

    wf_path = str(tmp_path / "wf.json")
    with open(wf_path, "w") as f:
        f.write('{"1": {"class_type": "KSampler", "inputs": {"steps": 20, "seed": 0}}}')

    config = ImageConfigFile.model_validate({
        "schema_version": 1,
        "enabled": True,
        "backend": {"type": "comfyui_http", "base_url": "http://127.0.0.1:8188", "mode": "external"},
        "limits": {"max_width": 2048, "max_height": 2048, "max_steps": 50, "timeout_seconds": 60.0},
        "presets": {"default": {"workflow_template": wf_path, "default_width": 1024, "default_height": 1024, "default_steps": 20}},
        "security": {"never_log_prompts": True},
        "artifacts_dir": artifacts_dir,
    })

    handler = ImageHandler(
        backend=FakeImageBackend(),
        config=config,
        event_logger=ev,
    )

    result = handler.handle(
        "system.image_generate",
        {
            "prompt": "a normal prompt",
            "negative_prompt": f"ugly {SECRET_MARKER} blurry",
        },
        {"trace_id": "t2"},
    )
    assert result["ok"] is True

    with open(events_path, "r", encoding="utf-8") as f:
        log_content = f.read()

    assert SECRET_MARKER not in log_content
