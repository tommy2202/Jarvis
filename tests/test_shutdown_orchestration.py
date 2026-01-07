from __future__ import annotations

import json
import os
import time

import pytest


class DummyOps:
    def __init__(self, path: str):
        self.path = path

    def log(self, *, trace_id: str, event: str, outcome: str, details=None):  # noqa: ANN001
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        with open(self.path, "a", encoding="utf-8") as f:
            f.write(json.dumps({"trace_id": trace_id, "event": event, "outcome": outcome, "details": details or {}}, ensure_ascii=False) + "\n")


class DummyRuntime:
    def __init__(self, calls):
        self.calls = calls
        self.voice_adapter = type("V", (), {"stop": lambda _s: calls.append("voice.stop")})()
        self.tts_adapter = type("T", (), {"stop": lambda _s: calls.append("tts.stop")})()

    def begin_shutdown(self, *, reason: str = "shutdown"):  # noqa: ANN001
        self.calls.append("runtime.begin_shutdown")

    def get_status(self):
        return {"state": "SLEEPING"}

    def request_shutdown(self):
        self.calls.append("runtime.request_shutdown")

    def stop(self):
        self.calls.append("runtime.stop")

    def set_voice_enabled(self, enabled: bool):  # noqa: ANN001
        self.calls.append(f"runtime.voice={enabled}")


class DummyJobs:
    def __init__(self, calls, hang: bool = False):
        self.calls = calls
        self.hang = hang

    def begin_shutdown(self):
        self.calls.append("jobs.begin_shutdown")

    def drain(self, *, grace_seconds: float, force_kill_after_seconds: float):  # noqa: ANN001
        self.calls.append("jobs.drain")
        if self.hang:
            time.sleep(1.0)
        return {"drained": True}

    def stop(self):
        self.calls.append("jobs.stop")

    def get_counts(self):
        return {"queued": 0, "running": 0, "total": 0}

    def restart_supervisor(self):
        self.calls.append("jobs.restart_supervisor")


def test_graceful_shutdown_order(tmp_path, monkeypatch):
    from jarvis.core.shutdown_orchestrator import ShutdownConfig, ShutdownMode, ShutdownOrchestrator

    monkeypatch.chdir(tmp_path)
    calls = []
    ops_path = str(tmp_path / "logs" / "ops.jsonl")
    orch = ShutdownOrchestrator(
        cfg=ShutdownConfig(phase_timeouts_seconds={"quiesce_inputs": 1, "drain_jobs": 1, "persist_flush": 1, "unload_resources": 1, "stop_services": 1}),
        ops=DummyOps(ops_path),
        logger=None,
        runtime=DummyRuntime(calls),
        job_manager=DummyJobs(calls),
        llm_lifecycle=None,
        telemetry=None,
        secure_store=None,
        config_manager=None,
        web_handle=None,
        ui_handle=None,
        root_path=".",
    )
    orch.run_shutdown_sequence(mode=ShutdownMode.GRACEFUL_STOP, reason="test", trace_id="t", safe_mode=False, argv=["app.py"])

    # verify phase order via ops log events
    lines = [json.loads(x) for x in open(ops_path, "r", encoding="utf-8").read().splitlines()]
    starts = [x["outcome"] for x in lines if x["event"] == "shutdown_phase_start"]
    assert starts[:6] == ["phase0_begin", "quiesce_inputs", "drain_jobs", "persist_flush", "unload_resources", "stop_services"]


def test_shutdown_blocks_new_requests(tmp_path, monkeypatch):
    from jarvis.core.runtime import JarvisRuntime, RuntimeConfig
    from jarvis.core.events import EventLogger

    monkeypatch.chdir(tmp_path)

    class DummyJarvis:
        def process_message(self, *_a, **_k):  # noqa: ANN001
            raise AssertionError("should not be called")

    rt = JarvisRuntime(cfg=RuntimeConfig(), jarvis_app=DummyJarvis(), event_logger=EventLogger("logs/events.jsonl"), logger=None)
    rt.begin_shutdown(reason="test")
    tid = rt.submit_text("cli", "hello")
    out = rt.get_result(tid)
    assert out is not None
    assert out["reply"].lower().startswith("shutting down")


def test_restart_marker_created_and_detected(tmp_path, monkeypatch):
    from jarvis.core.shutdown_orchestrator import ShutdownConfig, ShutdownMode, ShutdownOrchestrator
    from jarvis.core.runtime_control import RuntimeController, check_startup_recovery
    from jarvis.core.ops_log import OpsLogger

    monkeypatch.chdir(tmp_path)
    ops = OpsLogger(path=str(tmp_path / "logs" / "ops.jsonl"))

    def fake_exec(_exe, _argv):  # noqa: ANN001
        return

    orch = ShutdownOrchestrator(
        cfg=ShutdownConfig(phase_timeouts_seconds={"quiesce_inputs": 1, "drain_jobs": 1, "persist_flush": 1, "unload_resources": 1, "stop_services": 1}),
        ops=ops,
        logger=None,
        runtime=DummyRuntime([]),
        job_manager=None,
        llm_lifecycle=None,
        telemetry=None,
        secure_store=None,
        config_manager=None,
        web_handle=None,
        ui_handle=None,
        exec_fn=fake_exec,
        root_path=".",
    )
    ctl = RuntimeController(runtime_cfg={"shutdown": {"enable_restart": True, "restart_requires_admin": False}}, ops=ops, logger=None, orchestrator=orch, security_manager=None)
    ctl.request_shutdown(reason="test_restart", restart=True, safe_mode=True, argv=["app.py", "--ui"])
    # next startup should consume marker
    info = check_startup_recovery(ops=ops, root_path=".")
    assert info["restart"] is not None
    assert bool(info["restart"]["safe_mode"]) is True


def test_abrupt_shutdown_recovery(tmp_path, monkeypatch):
    from jarvis.core.ops_log import OpsLogger
    from jarvis.core.persistence.runtime_state import dirty_flag_path
    from jarvis.core.runtime_control import check_startup_recovery

    monkeypatch.chdir(tmp_path)
    os.makedirs(os.path.join("logs", "runtime"), exist_ok=True)
    with open(dirty_flag_path("."), "w", encoding="utf-8") as f:
        f.write("x\n")
    ops = OpsLogger(path=str(tmp_path / "logs" / "ops.jsonl"))
    info = check_startup_recovery(ops=ops, root_path=".")
    assert info["dirty_shutdown"] is True


def test_shutdown_timeout_triggers_force_stop(tmp_path, monkeypatch):
    from jarvis.core.shutdown_orchestrator import ShutdownConfig, ShutdownMode, ShutdownOrchestrator

    monkeypatch.chdir(tmp_path)
    calls = []
    ops_path = str(tmp_path / "logs" / "ops.jsonl")
    hanging_jobs = DummyJobs(calls, hang=True)
    orch = ShutdownOrchestrator(
        cfg=ShutdownConfig(phase_timeouts_seconds={"quiesce_inputs": 1, "drain_jobs": 0.1, "persist_flush": 1, "unload_resources": 1, "stop_services": 1}, job_grace_seconds=0.0, force_kill_after_seconds=0.0),
        ops=DummyOps(ops_path),
        logger=None,
        runtime=DummyRuntime(calls),
        job_manager=hanging_jobs,
        llm_lifecycle=None,
        telemetry=None,
        secure_store=None,
        config_manager=None,
        web_handle=None,
        ui_handle=None,
        root_path=".",
    )
    orch.run_shutdown_sequence(mode=ShutdownMode.GRACEFUL_STOP, reason="test", trace_id="t", safe_mode=False, argv=["app.py"])
    assert "jobs.stop" in calls

