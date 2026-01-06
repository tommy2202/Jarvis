from __future__ import annotations

import os
import time

import pytest

from jarvis.core.events import EventLogger
from jarvis.core.job_manager import (
    JobManager,
    SleepArgs,
    WriteTestFileArgs,
    job_system_health_check,
    job_system_sleep,
    job_system_sleep_llm,
    job_system_write_test_file,
)


class DummyLogger:
    def info(self, *_a, **_k): ...
    def warning(self, *_a, **_k): ...
    def error(self, *_a, **_k): ...


def _make_manager(tmp_path, *, max_concurrent=1):
    jobs_dir = str(tmp_path / "jobs")
    ev = EventLogger(str(tmp_path / "events.jsonl"))
    jm = JobManager(
        jobs_dir=jobs_dir,
        max_concurrent_jobs=max_concurrent,
        default_timeout_seconds=2,
        retention_max_jobs=200,
        retention_days=30,
        poll_interval_ms=50,
        event_logger=ev,
        logger=DummyLogger(),
    )
    jm.register_job("system.sleep", job_system_sleep, schema_model=SleepArgs)
    jm.register_job("system.health_check", job_system_health_check)
    jm.register_job("system.write_test_file", job_system_write_test_file, schema_model=WriteTestFileArgs)
    jm.register_job("system.sleep_llm", job_system_sleep_llm)
    return jm


def _wait_status(jm: JobManager, job_id: str, terminal: set[str], timeout: float = 5.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        st = jm.get_job(job_id)
        if st.status.value in terminal:
            return st
        time.sleep(0.05)
    raise AssertionError(f"Job {job_id} did not reach terminal state in time.")


def test_submit_job_transitions_to_succeeded(tmp_path):
    jm = _make_manager(tmp_path)
    try:
        job_id = jm.submit_job("system.sleep", {"seconds": 0.2}, {"source": "test"})
        st = _wait_status(jm, job_id, {"SUCCEEDED", "FAILED", "TIMED_OUT", "CANCELED"}, timeout=5.0)
        assert st.status.value == "SUCCEEDED"
        assert st.progress == 100
        # events file exists
        assert os.path.exists(os.path.join(jm.events_dir, f"{job_id}.jsonl"))
    finally:
        jm.stop()


def test_cancel_queued_job(tmp_path):
    jm = _make_manager(tmp_path, max_concurrent=1)
    try:
        job1 = jm.submit_job("system.sleep", {"seconds": 1.0}, {"source": "test"}, priority=10)
        job2 = jm.submit_job("system.sleep", {"seconds": 1.0}, {"source": "test"}, priority=20)
        ok = jm.cancel_job(job2)
        assert ok is True
        st2 = jm.get_job(job2)
        assert st2.status.value == "CANCELED"
        # job1 should eventually finish or be running; we don't require completion here.
    finally:
        jm.stop()


def test_timeout_job_marks_timed_out(tmp_path):
    jm = _make_manager(tmp_path)
    try:
        job_id = jm.submit_job("system.sleep", {"seconds": 2.0}, {"source": "test"}, max_runtime_seconds=1)
        st = _wait_status(jm, job_id, {"TIMED_OUT", "FAILED", "SUCCEEDED"}, timeout=5.0)
        assert st.status.value == "TIMED_OUT"
    finally:
        jm.stop()


def test_persistence_job_visible_after_restart(tmp_path):
    jm1 = _make_manager(tmp_path)
    try:
        job_id = jm1.submit_job("system.write_test_file", {"filename": "a.txt", "contents": "hi"}, {"source": "test"})
        st = _wait_status(jm1, job_id, {"SUCCEEDED", "FAILED", "TIMED_OUT", "CANCELED"}, timeout=5.0)
        assert st.status.value == "SUCCEEDED"
    finally:
        jm1.stop()

    jm2 = _make_manager(tmp_path)
    try:
        st2 = jm2.get_job(job_id)
        assert st2.status.value == "SUCCEEDED"
        assert st2.kind == "system.write_test_file"
    finally:
        jm2.stop()


def test_registry_unknown_kind_rejected(tmp_path):
    jm = _make_manager(tmp_path)
    try:
        with pytest.raises(ValueError):
            _ = jm.submit_job("unknown.kind", {}, {"source": "test"})
    finally:
        jm.stop()

