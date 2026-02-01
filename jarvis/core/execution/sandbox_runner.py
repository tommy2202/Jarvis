from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import time
from typing import Any, Dict, Optional

from jarvis.core.events import BaseEvent, EventSeverity, SourceSubsystem, redact
from jarvis.core.execution.models import ExecutionPlan, ExecutionRequest, ExecutionResult
from jarvis.core.broker.interface import ToolResult
from jarvis.core.broker.registry import ToolRegistry
from jarvis.core.broker.server import BrokerServer
from jarvis.core.broker.write_broker import WriteBroker
from jarvis.core.security_events import SecurityAuditLogger


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
    def __init__(
        self,
        *,
        config: Dict[str, Any] | None = None,
        logger=None,
        capability_engine: Any = None,
        policy_engine: Any = None,
        security_manager: Any = None,
        event_logger: Any = None,
        event_bus: Any = None,
        privacy_store: Any = None,
        secure_store: Any = None,
    ):
        self._config = dict(config or {})
        self._logger = logger
        self._capability_engine = capability_engine
        self._policy_engine = policy_engine
        self._security = security_manager
        self._event_logger = event_logger
        self._event_bus = event_bus
        self._privacy_store = privacy_store
        self._secure_store = secure_store

    def _resolve_secure_store(self):  # noqa: ANN001
        if self._secure_store is not None:
            return self._secure_store
        if self._security is None:
            return None
        return getattr(self._security, "secure_store", None)

    def _default_tool_registry(self) -> ToolRegistry:
        audit_logger = SecurityAuditLogger()
        registry = ToolRegistry(audit_logger=audit_logger)
        write_broker = WriteBroker(
            privacy_store=self._privacy_store,
            secure_store=self._resolve_secure_store(),
            audit_logger=audit_logger,
        )

        def _wrap_write(tool_name: str):  # noqa: ANN001
            return lambda args, ctx: write_broker.run(tool_name, args, ctx)

        for tool_name in ("write.memory", "write.transcript", "write.artifact_metadata"):
            registry.register(tool_name, _wrap_write(tool_name))

        def _echo(args: Dict[str, Any], context: Dict[str, Any]) -> ToolResult:
            trace_id = str((context or {}).get("trace_id") or "tool")
            return ToolResult(allowed=True, reason_code="ALLOWED", trace_id=trace_id, output={"echo": dict(args or {})})

        registry.register("core.echo", _echo)
        return registry

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
        metadata: Dict[str, Any] = {}
        warning: Dict[str, Any] | None = None
        if not self.is_available():
            return ExecutionResult(
                ok=False,
                backend=plan.backend,
                exec_mode=plan.mode,
                trace_id=request.trace_id,
                error="sandbox_unavailable",
                warning=warning,
                metadata=metadata,
            )

        cfg = dict(self._config or {})
        sandbox_cfg = cfg.get("sandbox") if isinstance(cfg.get("sandbox"), dict) else {}
        image = str((sandbox_cfg or {}).get("image") or "jarvis-sandbox:latest").strip()
        timeout_seconds = float((sandbox_cfg or {}).get("timeout_seconds", 30.0))
        cpus = (sandbox_cfg or {}).get("cpus")
        memory_mb = (sandbox_cfg or {}).get("memory_mb")
        pids_limit = (sandbox_cfg or {}).get("pids_limit")
        work_root = str((sandbox_cfg or {}).get("work_root") or os.path.join("runtime", "sandbox")).replace("\\", "/")
        broker_token_ttl = float((sandbox_cfg or {}).get("broker_token_ttl_seconds", 30.0))

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
            "required_capabilities": list(request.required_capabilities or []),
        }
        if request.execution_plan is not None:
            payload["execution_plan"] = request.execution_plan.model_dump(mode="json")
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
        broker_server: Optional[BrokerServer] = None
        plan_obj = request.execution_plan or plan
        plan_requires_broker = bool(plan_obj and plan_obj.tool_calls)
        if plan_requires_broker:
            tool_broker = request.tool_broker or self._default_tool_registry()
            broker_host = str((sandbox_cfg or {}).get("broker_host") or "host.docker.internal")
            bind_host = str((sandbox_cfg or {}).get("broker_bind_host") or ("127.0.0.1" if broker_host in {"127.0.0.1", "localhost"} else "0.0.0.0"))
            broker_cfg = sandbox_cfg.get("broker") if isinstance(sandbox_cfg.get("broker"), dict) else {}
            override_present = isinstance(broker_cfg, dict) and "allowed_client_cidrs" in broker_cfg
            if override_present:
                allowed_client_cidrs = broker_cfg.get("allowed_client_cidrs")
                if allowed_client_cidrs is None:
                    allowed_client_cidrs = []
                elif isinstance(allowed_client_cidrs, str):
                    allowed_client_cidrs = [allowed_client_cidrs]
                elif isinstance(allowed_client_cidrs, (list, tuple, set)):
                    allowed_client_cidrs = [str(item) for item in allowed_client_cidrs]
                else:
                    raise ValueError("execution.sandbox.broker.allowed_client_cidrs must be a list of CIDR strings")
            else:
                loopback_cidrs = ["127.0.0.1/32", "::1/128"]
                bind_host_norm = bind_host.strip().lower()
                if bind_host_norm in {"127.0.0.1", "localhost", "::1"}:
                    allowed_client_cidrs = list(loopback_cidrs)
                elif bind_host_norm == "0.0.0.0":
                    allowed_client_cidrs = list(loopback_cidrs) + ["172.16.0.0/12"]
                else:
                    allowed_client_cidrs = list(loopback_cidrs)
            broker_server = BrokerServer(
                tool_broker=tool_broker,
                capability_engine=self._capability_engine,
                policy_engine=self._policy_engine,
                security_manager=self._security,
                event_logger=self._event_logger,
                event_bus=self._event_bus,
                logger=self._logger,
                token_ttl_seconds=broker_token_ttl,
                bind_host=bind_host,
                allowed_client_cidrs=allowed_client_cidrs,
            )
            info = broker_server.start()
            token = str(info.get("token") or "")
            port = info.get("port")
            if not token or not port:
                broker_server.stop()
                shutil.rmtree(temp_root, ignore_errors=True)
                return ExecutionResult(
                    ok=False,
                    backend=plan.backend,
                    exec_mode=plan.mode,
                    trace_id=request.trace_id,
                    error="broker_unavailable",
                    warning=warning,
                    metadata=metadata,
                )
            if not str(broker_host or "").strip():
                broker_server.stop()
                shutil.rmtree(temp_root, ignore_errors=True)
                return ExecutionResult(
                    ok=False,
                    backend=plan.backend,
                    exec_mode=plan.mode,
                    trace_id=request.trace_id,
                    error="broker_unavailable",
                    warning=warning,
                    metadata=metadata,
                )
            endpoint = f"{broker_host}:{int(port)}"
            cmd += [
                "-e",
                f"BROKER_URL={endpoint}",
                "-e",
                f"BROKER_TOKEN={token}",
                "-e",
                f"JARVIS_BROKER_ENDPOINT={endpoint}",
                "-e",
                f"JARVIS_BROKER_TOKEN={token}",
            ]
            if broker_host == "host.docker.internal":
                cmd += ["--add-host", "host.docker.internal:host-gateway"]
            network_mode = str((sandbox_cfg or {}).get("broker_network_mode") or "bridge")
            cmd += ["--network", network_mode]
            if network_mode != "none":
                exception_details = {"reason_code": "BROKER_REQUIRED", "network_mode": network_mode, "trace_id": request.trace_id}
                warning = {"reason_code": "BROKER_REQUIRED", "network_mode": network_mode}
                if self._event_logger is not None:
                    self._event_logger.log(request.trace_id, "sandbox.network_exception", exception_details)
                if self._event_bus is not None:
                    try:
                        self._event_bus.publish_nowait(
                            BaseEvent(
                                event_type="sandbox.network_exception",
                                trace_id=request.trace_id,
                                source_subsystem=SourceSubsystem.dispatcher,
                                severity=EventSeverity.WARN,
                                payload=exception_details,
                            )
                        )
                    except Exception:
                        pass
                metadata = {
                    "warnings": ["Sandbox network exception enabled for broker connectivity."],
                    "network_exception": exception_details,
                }
        else:
            cmd += ["--network", "none"]

        cmd.append(image)

        try:
            subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_seconds)
        except subprocess.TimeoutExpired:
            try:
                subprocess.run(["docker", "rm", "-f", container_name], capture_output=True, text=True, timeout=5)
            except Exception:
                pass
            return ExecutionResult(
                ok=False,
                backend=plan.backend,
                exec_mode=plan.mode,
                trace_id=request.trace_id,
                error="sandbox_timeout",
                warning=warning,
                metadata=metadata,
            )
        finally:
            # allow slight flush time for container to write result.json
            time.sleep(0.05)
            if broker_server is not None:
                broker_server.stop()

        if not os.path.exists(res_path):
            shutil.rmtree(temp_root, ignore_errors=True)
            return ExecutionResult(
                ok=False,
                backend=plan.backend,
                exec_mode=plan.mode,
                trace_id=request.trace_id,
                error="sandbox_result_missing",
                warning=warning,
                metadata=metadata,
            )

        try:
            with open(res_path, "r", encoding="utf-8") as f:
                res = json.load(f)
        except Exception:
            shutil.rmtree(temp_root, ignore_errors=True)
            return ExecutionResult(
                ok=False,
                backend=plan.backend,
                exec_mode=plan.mode,
                trace_id=request.trace_id,
                error="sandbox_result_invalid",
                warning=warning,
                metadata=metadata,
            )

        ok = bool(res.get("ok", False))
        output = res.get("output") if isinstance(res.get("output"), dict) else None
        err = str(res.get("error") or "")
        shutil.rmtree(temp_root, ignore_errors=True)
        if ok:
            return ExecutionResult(
                ok=True,
                backend=plan.backend,
                exec_mode=plan.mode,
                trace_id=request.trace_id,
                output=output or {},
                warning=warning,
                metadata=metadata,
            )
        return ExecutionResult(
            ok=False,
            backend=plan.backend,
            exec_mode=plan.mode,
            trace_id=request.trace_id,
            error=err[:300],
            warning=warning,
            metadata=metadata,
        )
