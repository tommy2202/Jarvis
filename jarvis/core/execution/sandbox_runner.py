from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import time
from typing import Any, Dict

from jarvis.core.events import redact
from jarvis.core.execution.models import ExecutionPlan, ExecutionRequest, ExecutionResult


def _json_safe(obj: Any) -> Any:
    if isinstance(obj, dict):
        out: Dict[str, Any] = {}
        for k, v in obj.items():
            out[str(k)] = _json_safe(v)
        return out
    if isinstance(obj, list):
        return [_json_safe(v) for v in obj]
    if isinstance(obj, (str, int, float, bool)) or obj is None:
        return obj
    return str(obj)[:200]


class SandboxExecutionRunner:
    def __init__(self, *, config: Dict[str, Any] | None = None, logger=None):
        self._config = dict(config or {})
        self._logger = logger

    def update_config(self, config: Dict[str, Any]) -> None:
        self._config = dict(config or {})

    def is_available(self) -> bool:
        if shutil.which("docker") is None:
            return False
        try:
            res = subprocess.run(
                ["docker", "version", "--format", "{{.Server.Version}}"],
                capture_output=True,
                text=True,
                timeout=4,
            )
            return res.returncode == 0 and bool(str(res.stdout or "").strip())
        except Exception:
            return False

    def run(self, *, request: ExecutionRequest, plan: ExecutionPlan) -> ExecutionResult:
        if not self.is_available():
            return ExecutionResult(ok=False, backend=plan.backend, exec_mode=plan.mode, trace_id=request.trace_id, error="sandbox_unavailable")

        cfg = dict(self._config or {})
        sandbox_cfg = cfg.get("sandbox") if isinstance(cfg.get("sandbox"), dict) else {}
        image = str((sandbox_cfg or {}).get("image") or "jarvis-sandbox:latest").strip()
        timeout_seconds = float((sandbox_cfg or {}).get("timeout_seconds", 30.0))
        cpus = (sandbox_cfg or {}).get("cpus")
        memory_mb = (sandbox_cfg or {}).get("memory_mb")
        pids_limit = (sandbox_cfg or {}).get("pids_limit")
        work_root = str((sandbox_cfg or {}).get("work_root") or os.path.join("runtime", "sandbox")).replace("\\", "/")

        os.makedirs(work_root, exist_ok=True)
        temp_root = tempfile.mkdtemp(prefix="sandbox_", dir=work_root)
        input_dir = os.path.join(temp_root, "input")
        output_dir = os.path.join(temp_root, "output")
        work_dir = os.path.join(temp_root, "work")
        os.makedirs(input_dir, exist_ok=True)
        os.makedirs(output_dir, exist_ok=True)
        os.makedirs(work_dir, exist_ok=True)

        req_ctx = dict(request.context or {})
        req_ctx.pop("tool_broker", None)
        req_ctx.pop("secure_store", None)
        payload = {
            "trace_id": request.trace_id,
            "intent_id": request.intent_id,
            "module_id": request.module_id,
            "module_path": request.module_path,
            "args": redact(request.args or {}),
            "context": redact(req_ctx),
        }
        payload = _json_safe(payload)
        req_path = os.path.join(work_dir, "request.json")
        res_path = os.path.join(work_dir, "result.json")
        with open(req_path, "w", encoding="utf-8") as f:
            json.dump(payload, f, ensure_ascii=False)

        container_name = f"jarvis-sandbox-{request.trace_id[:12]}"
        cmd = [
            "docker",
            "run",
            "--rm",
            "--name",
            container_name,
            "--network",
            "none",
            "--workdir",
            "/work",
            "--mount",
            f"type=bind,src={os.path.abspath(input_dir)},dst=/input,readonly",
            "--mount",
            f"type=bind,src={os.path.abspath(output_dir)},dst=/output",
            "--mount",
            f"type=bind,src={os.path.abspath(work_dir)},dst=/work",
        ]
        if cpus:
            cmd += ["--cpus", str(cpus)]
        if memory_mb:
            cmd += ["--memory", f"{int(memory_mb)}m"]
        if pids_limit:
            cmd += ["--pids-limit", str(int(pids_limit))]
        cmd.append(image)

        try:
            subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_seconds)
        except subprocess.TimeoutExpired:
            try:
                subprocess.run(["docker", "rm", "-f", container_name], capture_output=True, text=True, timeout=5)
            except Exception:
                pass
            return ExecutionResult(ok=False, backend=plan.backend, exec_mode=plan.mode, trace_id=request.trace_id, error="sandbox_timeout")
        finally:
            # allow slight flush time for container to write result.json
            time.sleep(0.05)

        if not os.path.exists(res_path):
            shutil.rmtree(temp_root, ignore_errors=True)
            return ExecutionResult(ok=False, backend=plan.backend, exec_mode=plan.mode, trace_id=request.trace_id, error="sandbox_result_missing")

        try:
            with open(res_path, "r", encoding="utf-8") as f:
                res = json.load(f)
        except Exception:
            shutil.rmtree(temp_root, ignore_errors=True)
            return ExecutionResult(ok=False, backend=plan.backend, exec_mode=plan.mode, trace_id=request.trace_id, error="sandbox_result_invalid")

        ok = bool(res.get("ok", False))
        output = res.get("output") if isinstance(res.get("output"), dict) else None
        err = str(res.get("error") or "")
        shutil.rmtree(temp_root, ignore_errors=True)
        if ok:
            return ExecutionResult(ok=True, backend=plan.backend, exec_mode=plan.mode, trace_id=request.trace_id, output=output or {})
        return ExecutionResult(ok=False, backend=plan.backend, exec_mode=plan.mode, trace_id=request.trace_id, error=err[:300])
