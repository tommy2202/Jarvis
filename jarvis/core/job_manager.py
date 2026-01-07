from __future__ import annotations

import json
import os
import queue
import threading
import time
import uuid
from dataclasses import dataclass
from enum import Enum
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple, Type

import multiprocessing as mp
from pydantic import BaseModel, Field, ValidationError

from jarvis.core.events import EventLogger, redact
from jarvis.core.job_worker import worker_main


class JobStatus(str, Enum):
    QUEUED = "QUEUED"
    RUNNING = "RUNNING"
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    CANCELED = "CANCELED"
    TIMED_OUT = "TIMED_OUT"


class JobSpec(BaseModel):
    kind: str
    args: Dict[str, Any] = Field(default_factory=dict)
    requested_by: Dict[str, Any] = Field(default_factory=dict)
    created_at: float = Field(default_factory=lambda: time.time())
    max_runtime_seconds: Optional[int] = None
    priority: int = 50


class JobError(BaseModel):
    type: str
    message: str
    traceback: Optional[str] = None


class JobState(BaseModel):
    id: str
    status: JobStatus
    kind: str
    args: Dict[str, Any] = Field(default_factory=dict)
    progress: int = 0
    message: str = ""
    result: Optional[Dict[str, Any]] = None
    error: Optional[JobError] = None
    created_at: float
    started_at: Optional[float] = None
    finished_at: Optional[float] = None
    updated_at: float
    trace_id: str
    requested_by: Dict[str, Any] = Field(default_factory=dict)
    max_runtime_seconds: Optional[int] = None
    priority: int = 50


class JobEvent(BaseModel):
    timestamp: float = Field(default_factory=lambda: time.time())
    job_id: str
    event_type: str
    payload: Dict[str, Any] = Field(default_factory=dict)


@dataclass(frozen=True)
class JobHandler:
    handler_ref: str
    schema_model: Optional[Type[BaseModel]] = None


def _is_jsonable(x: Any) -> bool:
    try:
        json.dumps(x, ensure_ascii=False)
        return True
    except Exception:
        return False


def _atomic_write(path: str, data: Dict[str, Any]) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False, sort_keys=True)
        f.write("\n")
    os.replace(tmp, path)


class JobManager:
    """
    Production-grade, process-based job manager:
    - allowlisted job kinds only
    - spawn workers (Windows-compatible)
    - progress/log events from worker to main
    - cancellation + timeouts
    - persistence under logs/jobs/
    """

    def __init__(
        self,
        *,
        jobs_dir: str = os.path.join("logs", "jobs"),
        max_concurrent_jobs: int = 1,
        default_timeout_seconds: int = 600,
        retention_max_jobs: int = 200,
        retention_days: int = 30,
        poll_interval_ms: int = 200,
        event_logger: EventLogger,
        logger,
        debug_tracebacks: bool = False,
        post_complete_hooks: Optional[Dict[str, Callable[[JobState], None]]] = None,
        telemetry: Any = None,
    ):
        self.jobs_dir = jobs_dir
        self.events_dir = os.path.join(jobs_dir, "events")
        self.index_path = os.path.join(jobs_dir, "jobs_index.json")
        self.sandbox_dir = os.path.join(jobs_dir, "sandbox")

        self.max_concurrent_jobs = int(max_concurrent_jobs)
        self.default_timeout_seconds = int(default_timeout_seconds)
        self.retention_max_jobs = int(retention_max_jobs)
        self.retention_days = int(retention_days)
        self.poll_interval = max(0.05, float(poll_interval_ms) / 1000.0)

        self.event_logger = event_logger
        self.logger = logger
        self.debug_tracebacks = bool(debug_tracebacks)
        self.post_complete_hooks = post_complete_hooks or {}
        self.telemetry = telemetry

        self._ctx = mp.get_context("spawn")
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._supervisor = threading.Thread(target=self._run, name="jobs-supervisor", daemon=True)

        self._registry: Dict[str, JobHandler] = {}
        self._jobs: Dict[str, JobState] = {}
        self._exec_args: Dict[str, Dict[str, Any]] = {}
        self._queue: "queue.PriorityQueue[Tuple[int, float, str]]" = queue.PriorityQueue()
        self._canceled: set[str] = set()
        self._running: Dict[str, Dict[str, Any]] = {}  # job_id -> {proc,q,start_ts,deadline}

        os.makedirs(self.events_dir, exist_ok=True)
        os.makedirs(self.sandbox_dir, exist_ok=True)

        self._load_persisted()
        self._supervisor.start()

    # ---------- Registry ----------
    def register_job(self, kind: str, handler: Callable[..., Any], schema_model: Optional[Type[BaseModel]] = None) -> None:
        if not kind or not isinstance(kind, str):
            raise ValueError("kind must be a non-empty string")
        if ":" in kind or " " in kind:
            raise ValueError("kind must not contain ':' or spaces")
        if not callable(handler):
            raise ValueError("handler must be callable")
        # Ensure handler is importable by reference (required for spawn workers)
        mod = getattr(handler, "__module__", "")
        name = getattr(handler, "__name__", "")
        if not mod.startswith("jarvis.") or not name or name.startswith("<") or name.startswith("_"):
            raise ValueError("handler must be a top-level function under the 'jarvis.' package")
        ref = f"{mod}:{name}"
        self._registry[kind] = JobHandler(handler_ref=ref, schema_model=schema_model)

    def allowed_kinds(self) -> List[str]:
        return sorted(self._registry.keys())

    def get_counts(self) -> Dict[str, int]:
        """
        Read-only counts for telemetry/UI.
        """
        with self._lock:
            queued = sum(1 for j in self._jobs.values() if j.status == JobStatus.QUEUED)
            running = sum(1 for j in self._jobs.values() if j.status == JobStatus.RUNNING)
            return {"queued": int(queued), "running": int(running), "total": int(len(self._jobs))}

    # ---------- Public API ----------
    def submit_job(
        self,
        kind: str,
        args: Dict[str, Any],
        requested_by: Dict[str, Any],
        *,
        priority: int = 50,
        max_runtime_seconds: Optional[int] = None,
    ) -> str:
        if kind not in self._registry:
            raise ValueError("Unknown job kind (not allowlisted).")
        args = args or {}
        requested_by = requested_by or {}
        if not isinstance(args, dict) or not isinstance(requested_by, dict):
            raise ValueError("args/requested_by must be dict")
        if not _is_jsonable(args) or not _is_jsonable(requested_by):
            raise ValueError("args/requested_by must be JSON-serializable")

        handler = self._registry[kind]
        if handler.schema_model is not None:
            try:
                handler.schema_model.model_validate(args)
            except ValidationError as e:
                raise ValueError(f"Invalid args for {kind}: {e}") from e

        trace_id = uuid.uuid4().hex
        job_id = uuid.uuid4().hex
        spec = JobSpec(kind=kind, args=redact(args), requested_by=redact(requested_by), max_runtime_seconds=max_runtime_seconds, priority=int(priority))

        now = time.time()
        state = JobState(
            id=job_id,
            status=JobStatus.QUEUED,
            kind=kind,
            args=spec.args,
            progress=0,
            message="queued",
            result=None,
            error=None,
            created_at=float(spec.created_at),
            started_at=None,
            finished_at=None,
            updated_at=now,
            trace_id=trace_id,
            requested_by=spec.requested_by,
            max_runtime_seconds=spec.max_runtime_seconds,
            priority=spec.priority,
        )

        with self._lock:
            self._jobs[job_id] = state
            # Keep unredacted execution args in memory only (not persisted).
            self._exec_args[job_id] = dict(args)
            self._persist_index_locked()
            self._append_event_locked(job_id, JobEvent(job_id=job_id, event_type="created", payload={"kind": kind, "priority": spec.priority}).model_dump())
            self._queue.put((spec.priority, spec.created_at, job_id))

        self.event_logger.log(trace_id, "jobs.created", {"job_id": job_id, "kind": kind, "requested_by": spec.requested_by})
        if self.telemetry is not None:
            try:
                self.telemetry.set_gauge("jobs_queued", self.get_counts().get("queued", 0))
            except Exception:
                pass
        return job_id

    def cancel_job(self, job_id: str) -> bool:
        with self._lock:
            st = self._jobs.get(job_id)
            if not st:
                return False
            if st.status in {JobStatus.SUCCEEDED, JobStatus.FAILED, JobStatus.CANCELED, JobStatus.TIMED_OUT}:
                return False
            if st.status == JobStatus.QUEUED:
                self._canceled.add(job_id)
                st.status = JobStatus.CANCELED
                st.message = "canceled"
                st.updated_at = time.time()
                st.finished_at = st.updated_at
                self._append_event_locked(job_id, JobEvent(job_id=job_id, event_type="canceled", payload={}).model_dump())
                self._persist_index_locked()
                self._exec_args.pop(job_id, None)
                self.event_logger.log(st.trace_id, "jobs.canceled", {"job_id": job_id, "kind": st.kind})
                return True

            # RUNNING: terminate worker
            run = self._running.get(job_id)
            if run and run.get("proc") is not None:
                try:
                    run["cancel_requested"] = True
                    run["proc"].terminate()
                except Exception:
                    pass
            st.status = JobStatus.CANCELED
            st.message = "canceled"
            st.updated_at = time.time()
            st.finished_at = st.updated_at
            self._append_event_locked(job_id, JobEvent(job_id=job_id, event_type="canceled", payload={"running": True}).model_dump())
            self._persist_index_locked()
            self._exec_args.pop(job_id, None)
            self.event_logger.log(st.trace_id, "jobs.canceled", {"job_id": job_id, "kind": st.kind, "running": True})
            return True

    def get_job(self, job_id: str) -> JobState:
        with self._lock:
            st = self._jobs.get(job_id)
            if not st:
                raise KeyError(job_id)
            return JobState.model_validate(st.model_dump())

    def patch_job_result(self, job_id: str, patch: Dict[str, Any]) -> None:
        """
        Safely update a completed job's result in the persisted index.
        Intended for main-process post hooks (e.g., adding a health snapshot).
        """
        if not isinstance(patch, dict) or not _is_jsonable(patch):
            raise ValueError("patch must be JSON-serializable dict")
        with self._lock:
            st = self._jobs.get(job_id)
            if not st:
                raise KeyError(job_id)
            if st.result is None:
                st.result = {}
            st.result.update(redact(patch))
            st.updated_at = time.time()
            self._append_event_locked(job_id, JobEvent(job_id=job_id, event_type="log", payload={"message": "result_patched"}).model_dump())
            self._persist_index_locked()

    def list_jobs(self, *, status: Optional[str] = None, kind: Optional[str] = None, since: Optional[float] = None) -> List[JobState]:
        with self._lock:
            items = list(self._jobs.values())
        out: List[JobState] = []
        for st in items:
            if status and st.status.value != status:
                continue
            if kind and st.kind != kind:
                continue
            if since and st.created_at < since:
                continue
            out.append(st)
        out.sort(key=lambda s: s.created_at, reverse=True)
        return [JobState.model_validate(x.model_dump()) for x in out]

    def tail_job_events(self, job_id: str, last_n: int = 20) -> List[Dict[str, Any]]:
        path = os.path.join(self.events_dir, f"{job_id}.jsonl")
        if not os.path.exists(path):
            return []
        try:
            with open(path, "r", encoding="utf-8") as f:
                lines = f.readlines()
            tail = lines[-max(1, int(last_n)) :]
            return [json.loads(x) for x in tail]
        except Exception:
            return []

    def stop(self) -> None:
        self._stop.set()
        self._supervisor.join(timeout=2.0)
        with self._lock:
            for job_id, run in list(self._running.items()):
                proc = run.get("proc")
                if proc is not None and proc.is_alive():
                    try:
                        proc.terminate()
                    except Exception:
                        pass
            self._running.clear()
            self._exec_args.clear()
            self._persist_index_locked()

    def enforce_retention(self) -> None:
        self._enforce_retention()

    # ---------- Internal ----------
    def _load_persisted(self) -> None:
        if not os.path.exists(self.index_path):
            return
        try:
            with open(self.index_path, "r", encoding="utf-8") as f:
                raw = json.load(f)
        except Exception:
            return
        jobs = raw.get("jobs") or {}
        now = time.time()
        for job_id, st in jobs.items():
            try:
                js = JobState.model_validate(st)
            except Exception:
                continue
            # Mark RUNNING from last run as FAILED
            if js.status == JobStatus.RUNNING:
                js.status = JobStatus.FAILED
                js.message = "abrupt_shutdown"
                js.updated_at = now
                js.finished_at = now
                js.error = JobError(type="abrupt_shutdown", message="Job was running during previous shutdown.")
                try:
                    self._append_event_locked(js.id, JobEvent(job_id=js.id, event_type="error", payload={"type": "abrupt_shutdown", "message": js.error.message}).model_dump())
                    self._append_event_locked(js.id, JobEvent(job_id=js.id, event_type="finished", payload={"status": "FAILED"}).model_dump())
                except Exception:
                    pass
            self._jobs[job_id] = js
        # persist in case we changed any RUNNING jobs
        self._persist_index_locked()

    def _persist_index_locked(self) -> None:
        data = {"jobs": {jid: st.model_dump() for jid, st in self._jobs.items()}}
        _atomic_write(self.index_path, data)

    def _append_event_locked(self, job_id: str, event: Dict[str, Any]) -> None:
        os.makedirs(self.events_dir, exist_ok=True)
        path = os.path.join(self.events_dir, f"{job_id}.jsonl")
        with open(path, "a", encoding="utf-8") as f:
            f.write(json.dumps(event, ensure_ascii=False) + "\n")

    def _run(self) -> None:
        while not self._stop.is_set():
            self._poll_running()
            self._start_jobs_if_possible()
            time.sleep(self.poll_interval)

    def _start_jobs_if_possible(self) -> None:
        with self._lock:
            if len(self._running) >= self.max_concurrent_jobs:
                return

        # Pull from queue outside lock to avoid deadlocks.
        try:
            prio, created_at, job_id = self._queue.get_nowait()
        except queue.Empty:
            return

        with self._lock:
            if job_id in self._canceled:
                return
            st = self._jobs.get(job_id)
            if not st or st.status != JobStatus.QUEUED:
                return
            handler = self._registry.get(st.kind)
            if handler is None:
                st.status = JobStatus.FAILED
                st.message = "unknown_kind"
                st.updated_at = time.time()
                st.finished_at = st.updated_at
                st.error = JobError(type="unknown_kind", message="Job kind not registered.")
                self._persist_index_locked()
                return

            timeout = st.max_runtime_seconds if st.max_runtime_seconds is not None else self.default_timeout_seconds
            start_ts = time.time()
            deadline = start_ts + float(timeout)

            q = self._ctx.Queue()  # type: ignore[attr-defined]
            exec_args = self._exec_args.get(job_id) or dict(st.args or {})

            proc = self._ctx.Process(
                target=worker_main,
                args=(job_id, st.trace_id, {"args": exec_args, "debug_tracebacks": self.debug_tracebacks}, handler.handler_ref, q),
                daemon=True,
            )

            st.status = JobStatus.RUNNING
            st.started_at = start_ts
            st.updated_at = start_ts
            st.message = "running"
            self._append_event_locked(job_id, JobEvent(job_id=job_id, event_type="started", payload={"priority": st.priority}).model_dump())
            self._persist_index_locked()

            self._running[job_id] = {"proc": proc, "q": q, "start_ts": start_ts, "deadline": deadline}

        # metrics outside lock
        if self.telemetry is not None:
            try:
                wait_ms = float((start_ts - float(st.created_at)) * 1000.0)
                self.telemetry.record_latency("job_queue_wait_ms", wait_ms, tags={"kind": st.kind})
                self.telemetry.set_gauge("jobs_running", self.get_counts().get("running", 0))
                self.telemetry.set_gauge("jobs_queued", self.get_counts().get("queued", 0))
            except Exception:
                pass

        try:
            proc.start()
            self.event_logger.log(st.trace_id, "jobs.started", {"job_id": job_id, "kind": st.kind})
        except Exception as e:
            with self._lock:
                st = self._jobs.get(job_id)
                if st:
                    st.status = JobStatus.FAILED
                    st.message = "start_failed"
                    st.updated_at = time.time()
                    st.finished_at = st.updated_at
                    st.error = JobError(type="start_failed", message=str(e))
                    self._append_event_locked(job_id, JobEvent(job_id=job_id, event_type="error", payload={"type": "start_failed", "message": str(e)}).model_dump())
                    self._append_event_locked(job_id, JobEvent(job_id=job_id, event_type="finished", payload={"status": "FAILED"}).model_dump())
                    self._persist_index_locked()
                    self._running.pop(job_id, None)

    def _poll_running(self) -> None:
        now = time.time()
        finished: List[Tuple[str, JobStatus]] = []

        with self._lock:
            running_items = list(self._running.items())

        for job_id, run in running_items:
            proc = run.get("proc")
            q = run.get("q")
            deadline = float(run.get("deadline", 0))
            cancel_requested = bool(run.get("cancel_requested", False))

            if cancel_requested:
                try:
                    if proc is not None and proc.is_alive():
                        proc.terminate()
                except Exception:
                    pass

            # Timeout enforcement
            if deadline and now > deadline:
                try:
                    if proc is not None and proc.is_alive():
                        proc.terminate()
                except Exception:
                    pass
                with self._lock:
                    st = self._jobs.get(job_id)
                    if st and st.status == JobStatus.RUNNING:
                        st.status = JobStatus.TIMED_OUT
                        st.message = "timeout"
                        st.updated_at = time.time()
                        st.finished_at = st.updated_at
                        st.error = JobError(type="timeout", message="Job exceeded max_runtime_seconds.")
                        self._append_event_locked(job_id, JobEvent(job_id=job_id, event_type="timeout", payload={}).model_dump())
                        self._append_event_locked(job_id, JobEvent(job_id=job_id, event_type="finished", payload={"status": "TIMED_OUT"}).model_dump())
                        self._persist_index_locked()
                        self.event_logger.log(st.trace_id, "jobs.timeout", {"job_id": job_id, "kind": st.kind})
                        finished.append((job_id, JobStatus.TIMED_OUT))
                        self._exec_args.pop(job_id, None)
                continue

            # Drain worker events
            if q is not None:
                while True:
                    try:
                        msg = q.get_nowait()
                    except Exception:
                        break
                    self._handle_worker_msg(job_id, msg)

            # Process exit
            if proc is not None and not proc.is_alive():
                # ensure drained
                if q is not None:
                    while True:
                        try:
                            msg = q.get_nowait()
                        except Exception:
                            break
                        self._handle_worker_msg(job_id, msg)

                with self._lock:
                    st = self._jobs.get(job_id)
                    if st and st.status == JobStatus.RUNNING:
                        # If worker didn't send finished, mark failed
                        st.status = JobStatus.FAILED
                        st.message = "worker_exit"
                        st.updated_at = time.time()
                        st.finished_at = st.updated_at
                        st.error = JobError(type="worker_exit", message="Worker exited without completion.")
                        self._append_event_locked(job_id, JobEvent(job_id=job_id, event_type="error", payload={"type": "worker_exit"}).model_dump())
                        self._append_event_locked(job_id, JobEvent(job_id=job_id, event_type="finished", payload={"status": "FAILED"}).model_dump())
                        self._persist_index_locked()
                        finished.append((job_id, JobStatus.FAILED))
                        self._exec_args.pop(job_id, None)
                    elif st:
                        finished.append((job_id, st.status))

        if finished:
            with self._lock:
                for job_id, _ in finished:
                    self._running.pop(job_id, None)
            self._enforce_retention()

    def _handle_worker_msg(self, job_id: str, msg: Dict[str, Any]) -> None:
        et = msg.get("event_type")
        payload = msg.get("payload") or {}
        ts = float(msg.get("ts") or time.time())

        with self._lock:
            st = self._jobs.get(job_id)
            if not st:
                return
            # If main has already moved job to a terminal state (cancel/timeout), ignore worker events.
            if st.status in {JobStatus.CANCELED, JobStatus.TIMED_OUT}:
                return
            # Only accept worker events while RUNNING.
            if st.status != JobStatus.RUNNING and et in {"progress", "log", "error", "finished", "started"}:
                return

            if et == "progress":
                pct = int(payload.get("progress", st.progress))
                st.progress = max(0, min(100, pct))
                st.message = str(payload.get("message", st.message) or st.message)
                st.updated_at = time.time()
                self._append_event_locked(job_id, JobEvent(timestamp=ts, job_id=job_id, event_type="progress", payload={"progress": st.progress, "message": st.message}).model_dump())
                self._persist_index_locked()
                return

            if et == "log":
                # Persist logs as events; redact payload
                pl = redact(payload)
                self._append_event_locked(job_id, JobEvent(timestamp=ts, job_id=job_id, event_type="log", payload=pl).model_dump())
                self._persist_index_locked()
                return

            if et == "error":
                pl = redact(payload)
                st.error = JobError(type=str(pl.get("type", "error")), message=str(pl.get("message", "")), traceback=str(pl.get("traceback"))[:8000] if pl.get("traceback") else None)
                st.updated_at = time.time()
                self._append_event_locked(job_id, JobEvent(timestamp=ts, job_id=job_id, event_type="error", payload={"type": st.error.type, "message": st.error.message}).model_dump())
                self._persist_index_locked()
                return

            if et == "finished":
                status = str(payload.get("status") or "FAILED")
                if status == "SUCCEEDED":
                    st.status = JobStatus.SUCCEEDED
                    st.result = redact(payload.get("result") or {})
                    st.progress = 100
                    st.message = "succeeded"
                else:
                    st.status = JobStatus.FAILED
                    st.message = "failed"
                st.updated_at = time.time()
                st.finished_at = st.updated_at
                self._append_event_locked(job_id, JobEvent(timestamp=ts, job_id=job_id, event_type="finished", payload={"status": st.status.value}).model_dump())
                self._persist_index_locked()
                self.event_logger.log(st.trace_id, "jobs.finished", {"job_id": job_id, "kind": st.kind, "status": st.status.value})
                self._exec_args.pop(job_id, None)

        if et == "finished" and self.telemetry is not None:
            try:
                if st and st.started_at and st.finished_at:
                    rt_ms = float((float(st.finished_at) - float(st.started_at)) * 1000.0)
                    self.telemetry.record_latency("job_runtime_ms", rt_ms, tags={"kind": st.kind, "status": st.status.value})
                self.telemetry.set_gauge("jobs_running", self.get_counts().get("running", 0))
                self.telemetry.set_gauge("jobs_queued", self.get_counts().get("queued", 0))
            except Exception:
                pass

        # hooks outside lock
        try:
            hook = self.post_complete_hooks.get(st.kind) if st else None
            if hook and st:
                hook(self.get_job(job_id))
        except Exception as e:
            self.logger.error(f"[{getattr(st, 'trace_id', 'job')}] post-complete hook failed: {e}")

    def _enforce_retention(self) -> None:
        # Remove old jobs beyond max count and older than retention_days
        with self._lock:
            jobs = list(self._jobs.values())
        jobs.sort(key=lambda s: s.created_at, reverse=True)
        keep_ids = {j.id for j in jobs[: self.retention_max_jobs]}
        cutoff = time.time() - (float(self.retention_days) * 86400.0)
        for j in jobs:
            # Keep if either within max-jobs OR within retention-days.
            if j.id in keep_ids or j.created_at >= cutoff:
                continue
            # never delete running/queued jobs
            if j.status in {JobStatus.QUEUED, JobStatus.RUNNING}:
                continue
            self._delete_job_files(j.id)
            with self._lock:
                self._jobs.pop(j.id, None)
                self._persist_index_locked()

    def _delete_job_files(self, job_id: str) -> None:
        try:
            p = os.path.join(self.events_dir, f"{job_id}.jsonl")
            if os.path.exists(p):
                os.remove(p)
        except OSError:
            pass


# ---------- Core job handlers (allowlist) ----------
class SleepArgs(BaseModel):
    seconds: float = Field(ge=0.0, le=3600.0)


def job_system_sleep(args: Dict[str, Any], ctx) -> Dict[str, Any]:  # noqa: ANN001
    secs = float(args.get("seconds", 1.0))
    steps = max(1, int(secs / 0.2))
    for i in range(steps):
        time.sleep(secs / steps)
        ctx.progress(int((i + 1) * 100 / steps), "sleeping")
    return {"slept_seconds": secs}


def job_system_health_check(args: Dict[str, Any], ctx) -> Dict[str, Any]:  # noqa: ANN001
    ctx.log("health_check running")
    return {"status": "ok", "ts": time.time()}


class WriteTestFileArgs(BaseModel):
    filename: str = Field(default="job_test.txt", min_length=1, max_length=128)
    contents: str = Field(default="ok", max_length=10_000)


def job_system_write_test_file(args: Dict[str, Any], ctx) -> Dict[str, Any]:  # noqa: ANN001
    # Sandboxed to logs/jobs/sandbox
    base = os.path.join("logs", "jobs", "sandbox")
    os.makedirs(base, exist_ok=True)
    name = os.path.basename(str(args.get("filename") or "job_test.txt"))
    path = os.path.join(base, name)
    with open(path, "w", encoding="utf-8") as f:
        f.write(str(args.get("contents") or "ok"))
    ctx.progress(100, "written")
    return {"path": path}


def job_system_cleanup_jobs(args: Dict[str, Any], ctx) -> Dict[str, Any]:  # noqa: ANN001
    # Actual enforcement happens in main after completion; worker just proves job execution.
    ctx.log("cleanup requested")
    return {"requested": True}


def job_system_sleep_llm(args: Dict[str, Any], ctx) -> Dict[str, Any]:  # noqa: ANN001
    # Worker can't touch main-process LLM; main hook performs actual unload.
    ctx.log("sleep_llm requested")
    return {"requested": True}

