"""
Core handler for system.image_generate.

This handler is registered with the module registry and executed ONLY
via the dispatcher (single enforcement point).  The dispatcher enforces:
- CAP_IMAGE_GENERATION + CAP_HEAVY_COMPUTE capabilities
- Admin session required (hard rule via ADMIN_ONLY_CAPS)
- Denied in safe_mode and shutdown

This module does NOT perform any capability checks itself.
"""
from __future__ import annotations

import json
import os
import time
from typing import Any, Dict, Optional

from jarvis.core.events import EventLogger
from jarvis.core.image_backends.base import ImageBackend, ImageResult
from jarvis.core.image_backends.models import (
    ImageConfigFile,
    ImageLimitsConfig,
    ImagePresetConfig,
)


class ImageGenerationError(RuntimeError):
    """Safe error type for image generation failures."""
    pass


class ImageHandler:
    """
    Core handler for system.image_generate.

    Instantiated during app startup; the handle() method is registered
    with the module registry.
    """

    def __init__(
        self,
        *,
        backend: ImageBackend,
        config: ImageConfigFile,
        event_logger: EventLogger,
    ) -> None:
        self.backend = backend
        self.config = config
        self.event_logger = event_logger

    def handle(
        self, intent_id: str, args: Dict[str, Any], context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Handle system.image_generate.

        Args (from dispatcher):
            prompt: str (required)
            preset: str (default "default")
            width/height/steps/seed/negative_prompt: optional overrides

        Returns dict with:
            ok: bool
            reply: str (UX acknowledgment text)
            output_path: str (on success)
        """
        trace_id = str(context.get("trace_id") or context.get("_trace_id") or "img")
        t0 = time.time()

        # ── Extract args ──────────────────────────────────────────
        prompt = str(args.get("prompt") or "")
        if not prompt.strip():
            self.event_logger.log(trace_id, "image.generate.denied", {
                "denied_by": "handler",
                "reason_code": "empty_prompt",
            })
            return {"ok": False, "reply": "Image generation requires a prompt."}

        preset_name = str(args.get("preset") or "default")
        preset_cfg = self.config.presets.get(preset_name)
        if preset_cfg is None:
            self.event_logger.log(trace_id, "image.generate.denied", {
                "denied_by": "handler",
                "reason_code": "unknown_preset",
                "preset": preset_name,
            })
            return {"ok": False, "reply": f"Unknown preset: {preset_name}"}

        if isinstance(preset_cfg, dict):
            preset_cfg = ImagePresetConfig.model_validate(preset_cfg)

        limits = self.config.limits
        if isinstance(limits, dict):
            limits = ImageLimitsConfig.model_validate(limits)

        width = int(args.get("width") or preset_cfg.default_width)
        height = int(args.get("height") or preset_cfg.default_height)
        steps = int(args.get("steps") or preset_cfg.default_steps)
        seed = args.get("seed")
        if seed is not None:
            seed = int(seed)
        negative_prompt = args.get("negative_prompt") or preset_cfg.default_negative_prompt or None

        # ── Enforce limits (fail closed) ──────────────────────────
        if width > limits.max_width or height > limits.max_height:
            self.event_logger.log(trace_id, "image.generate.denied", {
                "denied_by": "limits",
                "reason_code": "size_exceeded",
                "requested_width": width,
                "requested_height": height,
                "max_width": limits.max_width,
                "max_height": limits.max_height,
            })
            return {
                "ok": False,
                "reply": f"Image size {width}x{height} exceeds limit {limits.max_width}x{limits.max_height}.",
            }

        if steps > limits.max_steps:
            self.event_logger.log(trace_id, "image.generate.denied", {
                "denied_by": "limits",
                "reason_code": "steps_exceeded",
                "requested_steps": steps,
                "max_steps": limits.max_steps,
            })
            return {
                "ok": False,
                "reply": f"Steps {steps} exceeds limit {limits.max_steps}.",
            }

        # ── Load workflow template ────────────────────────────────
        workflow_path = preset_cfg.workflow_template
        if not os.path.isfile(workflow_path):
            self.event_logger.log(trace_id, "image.generate.failed", {
                "error_code": "workflow_missing",
            })
            return {"ok": False, "reply": f"Workflow template not found: {workflow_path}"}

        try:
            with open(workflow_path, "r", encoding="utf-8") as f:
                workflow_json = json.load(f)
        except Exception:
            self.event_logger.log(trace_id, "image.generate.failed", {
                "error_code": "workflow_invalid_json",
            })
            return {"ok": False, "reply": "Workflow template is invalid JSON."}

        # ── Audit: metadata only (NEVER prompt) ──────────────────
        self.event_logger.log(trace_id, "image.generate.requested", {
            "preset": preset_name,
            "width": width,
            "height": height,
            "steps": steps,
            "seed_present": seed is not None,
        })

        # ── UX acknowledgment ─────────────────────────────────────
        ack_text = f"Generating an image (preset: {preset_name}, {width}x{height})..."

        # ── Check backend readiness ───────────────────────────────
        if not self.backend.is_ready():
            self.backend.ensure_ready()
        if not self.backend.is_ready():
            elapsed_ms = int((time.time() - t0) * 1000)
            self.event_logger.log(trace_id, "image.generate.failed", {
                "error_code": "backend_not_ready",
                "elapsed_ms": elapsed_ms,
            })
            return {"ok": False, "reply": "Image backend (ComfyUI) is not reachable."}

        # ── Generate ──────────────────────────────────────────────
        artifacts_dir = self.config.artifacts_dir
        if isinstance(artifacts_dir, str) and not artifacts_dir:
            artifacts_dir = "artifacts/images"

        try:
            result = self.backend.generate(
                prompt=prompt,
                preset=preset_name,
                width=width,
                height=height,
                steps=steps,
                seed=seed,
                negative_prompt=negative_prompt,
                trace_id=trace_id,
                timeout_seconds=limits.timeout_seconds,
                workflow_json=workflow_json,
                artifacts_dir=artifacts_dir,
            )
        except Exception as exc:
            elapsed_ms = int((time.time() - t0) * 1000)
            safe_error = type(exc).__name__
            self.event_logger.log(trace_id, "image.generate.failed", {
                "error_code": safe_error,
                "elapsed_ms": elapsed_ms,
            })
            return {"ok": False, "reply": f"Image generation failed: {safe_error}"}

        # ── Audit: completion ─────────────────────────────────────
        elapsed_ms = int((time.time() - t0) * 1000)
        self.event_logger.log(trace_id, "image.generate.completed", {
            "elapsed_ms": elapsed_ms,
            "output_path": result.output_path,
            "preset": result.preset,
            "width": result.width,
            "height": result.height,
            "steps": result.steps,
        })

        return {
            "ok": True,
            "reply": ack_text,
            "output_path": result.output_path,
        }
