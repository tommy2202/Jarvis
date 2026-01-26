from __future__ import annotations

import json
import os
import subprocess
import shutil

import pytest

from jarvis.core.capabilities.audit import CapabilityAuditLogger
from jarvis.core.capabilities.engine import CapabilityEngine
from jarvis.core.capabilities.loader import default_config_dict, validate_and_normalize
from jarvis.core.crypto import generate_usb_master_key_bytes, write_usb_key
from jarvis.core.dispatcher import Dispatcher
from jarvis.core.events import EventLogger
from jarvis.core.execution.models import ExecutionBackend, ExecutionPlan, ExecutionRequest
from jarvis.core.execution.sandbox_runner import SandboxExecutionRunner
from jarvis.core.module_registry import LoadedModule, ModuleRegistry
from jarvis.core.security import AdminSession, PermissionPolicy, SecurityManager
from jarvis.core.secure_store import SecureStore


class _L:
    def info(self, *_a, **_k): ...
    def warning(self, *_a, **_k): ...
    def error(self, *_a, **_k): ...


class _FakeSandboxRunner:
    def __init__(self, available: bool):
        self._available = bool(available)

    def update_config(self, _cfg):  # noqa: ANN001
        return None

    def is_available(self) -> bool:
        return bool(self._available)

    def run(self, *, request: ExecutionRequest, plan: ExecutionPlan):  # noqa: ANN001
        return None


def _make_dispatcher(tmp_path, *, execution_cfg: dict) -> Dispatcher:
    usb = tmp_path / "usb.bin"
    write_usb_key(str(usb), generate_usb_master_key_bytes())
    store = SecureStore(usb_key_path=str(usb), store_path=str(tmp_path / "store.enc"))
    sec = SecurityManager(secure_store=store, admin_session=AdminSession(timeout_seconds=999))
    sec.admin_session.unlock()

    raw = default_config_dict()
    raw["intent_requirements"]["demo.run"] = ["CAP_RUN_SUBPROCESS"]
    cap_cfg = validate_and_normalize(raw)
    cap_engine = CapabilityEngine(cfg=cap_cfg, audit=CapabilityAuditLogger(path=str(tmp_path / "security.jsonl")), logger=None)

    reg = ModuleRegistry()
    reg._modules_by_id["demo"] = LoadedModule(  # noqa: SLF001
        module_path="jarvis.modules.music",
        module_id="demo",
        meta={"resource_class": "light", "execution_mode": "thread", "required_capabilities": ["CAP_RUN_SUBPROCESS"]},
        _unsafe_handler=lambda **_k: {"summary": "ok"},
    )

    disp = Dispatcher(
        registry=reg,
        policy=PermissionPolicy(intents={}),
        security=sec,
        event_logger=EventLogger(str(tmp_path / "events.jsonl")),
        logger=_L(),
        capability_engine=cap_engine,
        secure_store=store,
        execution_config=execution_cfg,
    )
    return disp


def _read_events(path: str) -> list[dict]:
    if not os.path.exists(path):
        return []
    out = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            try:
                out.append(json.loads(line))
            except Exception:
                continue
    return out


def test_docker_missing_require_available_denies(tmp_path):
    exec_cfg = {
        "enabled": True,
        "default_backend": "sandbox",
        "fallback_backend": "local_thread",
        "sandbox": {"require_available": True},
        "allow_inline_intents": [],
    }
    disp = _make_dispatcher(tmp_path, execution_cfg=exec_cfg)
    disp.sandbox_runner = _FakeSandboxRunner(available=False)

    res = disp.dispatch("t1", "demo.run", "demo", {}, {"source": "cli"})
    assert res.ok is False
    assert res.denied_reason == "sandbox_unavailable"
    assert "Docker" in (res.remediation or "")


def test_docker_missing_fallback_local_audited(tmp_path):
    exec_cfg = {
        "enabled": True,
        "default_backend": "sandbox",
        "fallback_backend": "local_thread",
        "sandbox": {"require_available": False},
        "allow_inline_intents": [],
    }
    disp = _make_dispatcher(tmp_path, execution_cfg=exec_cfg)
    disp.sandbox_runner = _FakeSandboxRunner(available=False)

    res = disp.dispatch("t2", "demo.run", "demo", {}, {"source": "cli"})
    assert res.ok is True

    rows = _read_events(str(tmp_path / "events.jsonl"))
    assert any(r.get("event") == "execution.sandbox_fallback" for r in rows)


def _docker_image_available(image: str) -> bool:
    if shutil.which("docker") is None:
        return False
    try:
        res = subprocess.run(["docker", "image", "inspect", image], capture_output=True, text=True, timeout=4)
        return res.returncode == 0
    except Exception:
        return False


@pytest.mark.skipif(not _docker_image_available("jarvis-sandbox:latest"), reason="sandbox image not available")
def test_sandbox_integration_trivial_handler(tmp_path):
    req = ExecutionRequest(
        trace_id="t3",
        intent_id="music.play",
        module_id="music",
        args={"song": "x", "service": "y"},
        context={"source": "cli"},
        required_capabilities=["CAP_AUDIO_OUTPUT"],
        execution_mode="process",
        is_core=False,
        allow_inline_intents=[],
        default_backend=ExecutionBackend.sandbox,
        fallback_backend=ExecutionBackend.local_process,
        sandbox_require_available=True,
        sandbox_available=True,
        module_path="jarvis.modules.music",
        persist_allowed=True,
    )
    plan = ExecutionPlan(backend=ExecutionBackend.sandbox, mode="sandbox", reason="test", fallback_used=False)
    runner = SandboxExecutionRunner(config={"sandbox": {"image": "jarvis-sandbox:latest", "require_available": True}}, logger=None)
    res = runner.run(request=req, plan=plan)
    assert res.ok is True
