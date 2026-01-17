from __future__ import annotations

import json
import os
import time

from jarvis.core.events import EventLogger
from jarvis.core.job_manager import JobManager, JobStatus, job_system_checkpoint_demo


class _L:
    def info(self, *_a, **_k): ...
    def warning(self, *_a, **_k): ...
    def error(self, *_a, **_k): ...


class _Bus:
    def __init__(self) -> None:
        self.events: list[object] = []

    def publish_nowait(self, ev) -> None:  # noqa: ANN001
        self.events.append(ev)


def test_job_persists_state(tmp_path):
    jobs_dir = str(tmp_path / "jobs")
    bus = _Bus()
    jm = JobManager(jobs_dir=jobs_dir, event_logger=EventLogger(str(tmp_path / "events.jsonl")), logger=_L(), poll_interval_ms=50, event_bus=bus)
    jm.register_job("system.checkpoint_demo", job_system_checkpoint_demo, required_capabilities=["CAP_RUN_SUBPROCESS"])
    jid = jm.submit_job("system.checkpoint_demo", {"step": 7}, {"source": "cli"}, internal_call=True)

    # wait for completion
    deadline = time.time() + 5.0
    while time.time() < deadline:
        st = jm.get_job(jid)
        if st.status in {JobStatus.SUCCEEDED, JobStatus.FAILED, JobStatus.CANCELED, JobStatus.TIMED_OUT}:
            break
        time.sleep(0.05)
    st = jm.get_job(jid)
    jm.stop()
    assert st.status == JobStatus.SUCCEEDED

    with open(os.path.join(jobs_dir, "jobs_index.json"), "r", encoding="utf-8") as f:
        raw = json.load(f)
    rec = raw["jobs"][jid]
    assert rec["job_id"] == jid
    assert rec["state"] == "completed"
    assert rec["checkpoint"] == {"step": 7}


def test_restart_marks_job_failed(tmp_path):
    jobs_dir = str(tmp_path / "jobs")
    os.makedirs(jobs_dir, exist_ok=True)
    jid = "job1"
    with open(os.path.join(jobs_dir, "jobs_index.json"), "w", encoding="utf-8") as f:
        json.dump(
            {
                "jobs": {
                    jid: {
                        "id": jid,
                        "status": "RUNNING",
                        "kind": "system.checkpoint_demo",
                        "args": {},
                        "checkpoint": {"step": 1},
                        "progress": 10,
                        "message": "running",
                        "result": None,
                        "error": None,
                        "created_at": 1.0,
                        "started_at": 2.0,
                        "finished_at": None,
                        "updated_at": 2.0,
                        "trace_id": "t",
                        "requested_by": {"source": "cli"},
                        "max_runtime_seconds": None,
                        "priority": 50,
                        "heavy": False,
                    }
                }
            },
            f,
        )
        f.write("\n")

    bus = _Bus()
    jm = JobManager(jobs_dir=jobs_dir, event_logger=EventLogger(str(tmp_path / "events.jsonl")), logger=_L(), max_concurrent_jobs=0, poll_interval_ms=1000, event_bus=bus)
    st = jm.get_job(jid)
    jm.stop()
    assert st.status == JobStatus.FAILED
    assert st.error is not None
    assert st.error.type == "failed_due_to_restart"
    assert any(getattr(ev, "event_type", "") == "job.failed_due_to_restart" for ev in bus.events)


def test_resume_requires_admin(tmp_path):
    jobs_dir = str(tmp_path / "jobs")
    os.makedirs(jobs_dir, exist_ok=True)
    jid = "job2"
    with open(os.path.join(jobs_dir, "jobs_index.json"), "w", encoding="utf-8") as f:
        json.dump(
            {
                "jobs": {
                    jid: {
                        "id": jid,
                        "status": "FAILED",
                        "kind": "system.checkpoint_demo",
                        "args": {"step": 3},
                        "checkpoint": {"step": 2},
                        "progress": 20,
                        "message": "failed_due_to_restart",
                        "result": None,
                        "error": {"type": "failed_due_to_restart", "message": "x"},
                        "created_at": 1.0,
                        "started_at": 2.0,
                        "finished_at": 3.0,
                        "updated_at": 3.0,
                        "trace_id": "t",
                        "requested_by": {"source": "cli"},
                        "max_runtime_seconds": None,
                        "priority": 50,
                        "heavy": False,
                    }
                }
            },
            f,
        )
        f.write("\n")

    jm = JobManager(jobs_dir=jobs_dir, event_logger=EventLogger(str(tmp_path / "events.jsonl")), logger=_L(), max_concurrent_jobs=0, poll_interval_ms=1000, event_bus=None)
    assert jm.resume_job(jid, is_admin=False, trace_id="t") is False
    assert jm.resume_job(jid, is_admin=True, trace_id="t") is True
    st = jm.get_job(jid)
    jm.stop()
    assert st.status == JobStatus.QUEUED

