"""
ComfyUI HTTP backend for image generation.

Flow:
1. Health check via GET /system_stats
2. Submit workflow via POST /prompt
3. Poll for completion via GET /history/{prompt_id}
4. Download image via GET /view?filename=...&subfolder=...&type=output
5. Save to artifacts/images/<timestamp>_<trace_id>_<preset>.png
"""
from __future__ import annotations

import hashlib
import json
import os
import time
from typing import Any, Dict, Optional

import requests

from jarvis.core.image_backends.base import BackendHealth, ImageBackend, ImageResult


class ComfyUIBackend(ImageBackend):
    """ComfyUI HTTP backend (localhost only)."""

    name: str = "comfyui"

    def __init__(self, *, base_url: str = "http://127.0.0.1:8188") -> None:
        self.base_url = base_url.rstrip("/")

    def _url(self, path: str) -> str:
        return f"{self.base_url}{path}"

    # ── readiness ──────────────────────────────────────────────────

    def health(self) -> BackendHealth:
        try:
            r = requests.get(self._url("/system_stats"), timeout=3.0)
            if r.status_code == 200:
                return BackendHealth(ok=True, detail="ok")
            return BackendHealth(ok=False, detail=f"HTTP {r.status_code}")
        except Exception as e:  # noqa: BLE001
            return BackendHealth(ok=False, detail=str(e))

    def ensure_ready(self) -> None:
        """Validate ComfyUI is reachable.  We never auto-start ComfyUI."""
        # No-op: external mode only.
        pass

    def is_ready(self) -> bool:
        return self.health().ok

    def release(self) -> None:
        pass

    # ── generation ─────────────────────────────────────────────────

    def generate(
        self,
        *,
        prompt: str,
        preset: str,
        width: int,
        height: int,
        steps: int,
        seed: Optional[int] = None,
        negative_prompt: Optional[str] = None,
        trace_id: str,
        timeout_seconds: float,
        workflow_json: Dict[str, Any],
        artifacts_dir: str = "artifacts/images",
    ) -> ImageResult:
        """Submit workflow to ComfyUI, poll, download, and save."""
        workflow_hash = hashlib.sha256(
            json.dumps(workflow_json, sort_keys=True).encode()
        ).hexdigest()[:16]

        # Inject parameters into the workflow
        workflow = _inject_params(
            workflow_json,
            prompt=prompt,
            negative_prompt=negative_prompt or "",
            width=width,
            height=height,
            steps=steps,
            seed=seed,
        )

        # Submit
        prompt_id = self._submit(workflow, timeout_seconds)

        # Poll
        output_info = self._poll(prompt_id, timeout_seconds)

        # Download
        image_bytes = self._download_image(output_info, timeout_seconds)

        # Save
        os.makedirs(artifacts_dir, exist_ok=True)
        ts = time.strftime("%Y%m%d_%H%M%S", time.gmtime())
        safe_trace = "".join(c for c in trace_id if c.isalnum() or c in "-_")[:32]
        safe_preset = "".join(c for c in preset if c.isalnum() or c in "-_")[:32]
        filename = f"{ts}_{safe_trace}_{safe_preset}.png"
        output_path = os.path.join(artifacts_dir, filename)

        with open(output_path, "wb") as f:
            f.write(image_bytes)

        return ImageResult(
            output_path=output_path,
            preset=preset,
            seed=seed,
            width=width,
            height=height,
            steps=steps,
            workflow_hash=workflow_hash,
        )

    # ── HTTP helpers ───────────────────────────────────────────────

    def _submit(self, workflow: Dict[str, Any], timeout_seconds: float) -> str:
        """POST /prompt and return prompt_id."""
        payload = {"prompt": workflow}
        r = requests.post(
            self._url("/prompt"),
            json=payload,
            timeout=min(timeout_seconds, 30.0),
        )
        r.raise_for_status()
        data = r.json()
        prompt_id = data.get("prompt_id")
        if not prompt_id:
            raise RuntimeError("ComfyUI /prompt response missing prompt_id")
        return str(prompt_id)

    def _poll(self, prompt_id: str, timeout_seconds: float) -> Dict[str, Any]:
        """Poll GET /history/{prompt_id} until completion or timeout."""
        deadline = time.time() + timeout_seconds
        poll_interval = 1.0
        while time.time() < deadline:
            try:
                r = requests.get(
                    self._url(f"/history/{prompt_id}"),
                    timeout=5.0,
                )
                if r.status_code == 200:
                    data = r.json()
                    entry = data.get(prompt_id)
                    if entry and entry.get("outputs"):
                        # Find the first image output
                        for node_id, node_out in entry["outputs"].items():
                            images = node_out.get("images")
                            if images and len(images) > 0:
                                return images[0]
            except requests.RequestException:
                pass
            time.sleep(poll_interval)

        raise requests.Timeout(
            f"ComfyUI generation did not complete within {timeout_seconds}s"
        )

    def _download_image(
        self, image_info: Dict[str, Any], timeout_seconds: float
    ) -> bytes:
        """GET /view?filename=...&subfolder=...&type=output."""
        params = {
            "filename": image_info.get("filename", ""),
            "subfolder": image_info.get("subfolder", ""),
            "type": image_info.get("type", "output"),
        }
        r = requests.get(
            self._url("/view"),
            params=params,
            timeout=min(timeout_seconds, 60.0),
        )
        r.raise_for_status()
        if len(r.content) == 0:
            raise RuntimeError("ComfyUI returned empty image")
        return r.content


# ---------------------------------------------------------------------------
# Workflow parameter injection
# ---------------------------------------------------------------------------


def _inject_params(
    workflow: Dict[str, Any],
    *,
    prompt: str,
    negative_prompt: str,
    width: int,
    height: int,
    steps: int,
    seed: Optional[int],
) -> Dict[str, Any]:
    """
    Walk through the workflow JSON and inject parameters into known node types.

    ComfyUI workflows are node graphs. We look for node class_type keys
    and inject values into the appropriate inputs.
    """
    import copy

    wf = copy.deepcopy(workflow)
    for node_id, node in wf.items():
        if not isinstance(node, dict):
            continue
        ct = node.get("class_type", "")
        inputs = node.get("inputs", {})
        if not isinstance(inputs, dict):
            continue

        # Positive prompt (CLIPTextEncode is the standard text node)
        if ct == "CLIPTextEncode" and "text" in inputs:
            if inputs.get("_role") == "negative":
                inputs["text"] = negative_prompt
            else:
                inputs["text"] = prompt

        # Image dimensions (EmptyLatentImage or similar)
        if ct == "EmptyLatentImage":
            if "width" in inputs:
                inputs["width"] = width
            if "height" in inputs:
                inputs["height"] = height

        # Steps (KSampler)
        if ct == "KSampler":
            if "steps" in inputs:
                inputs["steps"] = steps
            if seed is not None and "seed" in inputs:
                inputs["seed"] = seed

    return wf
