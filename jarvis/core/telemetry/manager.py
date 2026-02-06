from __future__ import annotations

import json
import os
import threading
import time
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutureTimeout
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field

from jarvis.core.telemetry.events import TelemetryEventWriter
from jarvis.core.telemetry.health_checks import CheckSpec, degraded, down, ok, unknown
from jarvis.core.telemetry.metrics import RollingMetrics
from jarvis.core.telemetry.models import HealthCheckResult, HealthEvent, HealthStatus, MetricSummary, ResourceSample, Subsystem, TelemetrySnapshot
from jarvis.core.telemetry.redaction import telemetry_redact
from jarvis.core.telemetry.resources import ResourceSampler, ResourceThresholds


class TelemetryConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool = True
    poll_interval_seconds: float = 5.0
    sample_interval_seconds: float = 5.0
    max_samples_per_histogram: int = 200
    retention_days: int = 14
    thresholds: Dict[str, float] = Field(
        default_factory=lambda: {
            "cpu_warn_percent": 85,
            "ram_warn_percent": 85,
            "disk_warn_percent_used": 90,
            "gpu_vram_warn_percent": 90,
        }
    )
    gpu: Dict[str, Any] = Field(default_factory=lambda: {"enable_nvml": True})


@dataclass
class WebServerInfo:
    enabled: bool
    bind_host: str
    port: int
    allow_remote: bool
    thread_alive: bool


class TelemetryManager:
    """
    Production-grade local telemetry.
    Thread-safe API for metrics + a background loop for health/resource sampling.
    """

    def __init__(self, *, cfg: TelemetryConfig, logger=None, root_path: str = ".", privacy_store: Any = None):
        self.cfg = cfg
        self.logger = logger
        self.root_path = root_path
        self.privacy_store = privacy_store
        self._start_ts = time.time()

        self.metrics = RollingMetrics(max_samples_per_histogram=int(cfg.max_samples_per_histogram))
        self._event_writer = TelemetryEventWriter(privacy_store=privacy_store)
        self._sampler = ResourceSampler(root_path=root_path, logs_path=os.path.join(root_path, "logs"), enable_nvml=bool((cfg.gpu or {}).get("enable_nvml", True)))
        try:
            self._thresholds = ResourceThresholds(**(cfg.thresholds or {}))
        except Exception:
            self._thresholds = ResourceThresholds()

        self._lock = threading.Lock()
        self._health: Dict[Subsystem, HealthCheckResult] = {}
        self._last_resources = ResourceSample(sampled_at=time.time())
        self._web: Optional[WebServerInfo] = None
        self._ui_last_heartbeat: Optional[float] = None

        self._deps: Dict[str, Any] = {}

        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._loop, name="telemetry", daemon=True)
        self._exec = ThreadPoolExecutor(max_workers=8, thread_name_prefix="telemetry-check")

        self._cleanup_retention()
        # Ensure telemetry event log exists (local-only).
        try:
            self._event_writer.emit(HealthEvent(trace_id="telemetry", event_type="telemetry_started", message="telemetry started", details={"enabled": bool(self.cfg.enabled)}))
        except Exception:
            pass
        if self.cfg.enabled:
            self._thread.start()

    # -------- wiring --------
    def attach(self, **deps: Any) -> None:
        """
        Attach subsystem references used for active checks (read-only).
        Expected keys (optional): config_manager, secure_store, runtime, jarvis_app, dispatcher, job_manager, llm_lifecycle, voice_adapter, tts_adapter
        """
        with self._lock:
            self._deps.update(deps)

    def set_web_server_info(self, *, enabled: bool, bind_host: str, port: int, allow_remote: bool, thread_alive: bool) -> None:
        with self._lock:
            self._web = WebServerInfo(enabled=bool(enabled), bind_host=str(bind_host), port=int(port), allow_remote=bool(allow_remote), thread_alive=bool(thread_alive))

    def ui_heartbeat(self) -> None:
        with self._lock:
            self._ui_last_heartbeat = time.time()

    # -------- public metrics API --------
    def increment_counter(self, name: str, n: int = 1, tags: Optional[Dict[str, Any]] = None) -> None:
        if not self.cfg.enabled:
            return
        self.metrics.inc(name, n=n, tags=telemetry_redact(tags or {}))

    def set_gauge(self, name: str, value: Any, tags: Optional[Dict[str, Any]] = None) -> None:
        if not self.cfg.enabled:
            return
        self.metrics.set_gauge(name, telemetry_redact(value), tags=telemetry_redact(tags or {}))

    def record_latency(self, name: str, ms: float, tags: Optional[Dict[str, Any]] = None) -> None:
        if not self.cfg.enabled:
            return
        self.metrics.observe(name, float(ms), tags=telemetry_redact(tags or {}))

    def record_error(self, *, subsystem: str, severity: str, error_code: str, trace_id: str) -> None:
        # counters only (no secrets)
        self.increment_counter("errors_total", 1, tags={"subsystem": subsystem, "severity": severity})
        # Passive health degrade
        try:
            ss = Subsystem(subsystem)
        except Exception:
            return
        with self._lock:
            prev = self._health.get(ss)
            # if no active checks yet, synthesize a degraded result
            if prev is None:
                self._health[ss] = degraded(ss, "errors observed", error_code=error_code, details={"passive": True})
                self._emit_if_changed(ss, None, self._health[ss], trace_id=trace_id)
            else:
                prev.consecutive_failures = int(prev.consecutive_failures) + 1
                if prev.status == HealthStatus.OK:
                    prev.status = HealthStatus.DEGRADED
                    prev.message = "errors observed"
                    prev.error_code = error_code
                    prev.last_checked_at = time.time()
                    self._emit_if_changed(ss, HealthStatus.OK, prev, trace_id=trace_id)

    # -------- snapshots --------
    def get_health(self, subsystem: Optional[str] = None) -> List[Dict[str, Any]]:
        with self._lock:
            items = list(self._health.values())
        if subsystem:
            try:
                ss = Subsystem(subsystem)
            except Exception:
                return []
            items = [x for x in items if x.subsystem == ss]
        return [x.model_dump() for x in items]

    def get_metrics_summary(self) -> Dict[str, Any]:
        snap = self.metrics.snapshot()
        return snap

    def get_snapshot(self) -> Dict[str, Any]:
        with self._lock:
            health = [x for x in self._health.values()]
            resources = self._last_resources
            recent = self._event_writer.recent(50)
        ms = self.metrics.snapshot()
        summary = MetricSummary.model_validate(ms)
        snap = TelemetrySnapshot(
            uptime_seconds=float(time.time() - self._start_ts),
            health=health,
            metrics=summary,
            resources=resources,
            recent_events=[HealthEvent.model_validate(x) for x in recent],
        )
        return snap.model_dump()

    def export_snapshot(self, path: str) -> str:
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        payload = self.get_snapshot()
        with open(path, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2, ensure_ascii=False)
        return path

    def export_snapshot_to_default_dir(self) -> str:
        ts = time.strftime("%Y%m%d_%H%M%S", time.gmtime())
        out_dir = os.path.join("logs", "telemetry", "snapshots")
        os.makedirs(out_dir, exist_ok=True)
        return self.export_snapshot(os.path.join(out_dir, f"snapshot.{ts}.json"))

    def reset(self) -> None:
        self.metrics.reset()
        with self._lock:
            self._health.clear()
        self._event_writer.emit(HealthEvent(trace_id="telemetry", event_type="telemetry_reset", message="telemetry reset", details={}))

    def stop(self) -> None:
        self._stop.set()
        try:
            self._thread.join(timeout=2.0)
        except Exception:
            pass
        try:
            self._exec.shutdown(wait=False, cancel_futures=True)
        except Exception:
            pass

    # -------- internal loop --------
    def _loop(self) -> None:
        # Allow faster polling in tests; keep a small floor to avoid tight loops.
        poll = max(0.2, float(self.cfg.poll_interval_seconds))
        sample = max(0.2, float(self.cfg.sample_interval_seconds))
        next_health = time.time()
        next_sample = time.time()
        while not self._stop.is_set():
            now = time.time()
            # uptime gauge
            try:
                self.set_gauge("uptime_seconds", float(now - self._start_ts))
            except Exception:
                pass
            if now >= next_sample:
                self._sample_resources()
                next_sample = now + sample
            if now >= next_health:
                self._run_checks()
                next_health = now + poll
            time.sleep(0.2)

    def _run_checks(self) -> None:
        specs = self._build_checks()
        for spec in specs:
            t0 = time.time()
            fut = self._exec.submit(spec.fn)
            try:
                res = fut.result(timeout=float(spec.timeout_seconds))
                res.latency_ms = float((time.time() - t0) * 1000.0)
            except FutureTimeout:
                res = degraded(spec.subsystem, "health check timeout", error_code="timeout", remediation="Check subsystem thread health.")
                res.latency_ms = float((time.time() - t0) * 1000.0)
            except Exception as e:  # noqa: BLE001
                res = degraded(spec.subsystem, "health check error", error_code="check_error", details={"error": str(e)}, remediation="Check logs for details.")
                res.latency_ms = float((time.time() - t0) * 1000.0)

            with self._lock:
                prev = self._health.get(spec.subsystem)
                old_status = prev.status if prev else None
                # maintain last_ok_at + consecutive_failures
                if res.status == HealthStatus.OK:
                    res.last_ok_at = time.time()
                    res.consecutive_failures = 0
                else:
                    res.last_ok_at = prev.last_ok_at if prev else None
                    res.consecutive_failures = int((prev.consecutive_failures if prev else 0) + 1)
                self._health[spec.subsystem] = res
                self._emit_if_changed(spec.subsystem, old_status, res, trace_id="telemetry")

        # Derived gauges (best-effort)
        with self._lock:
            deps = dict(self._deps)
        sec = deps.get("security_manager")
        if sec is not None:
            try:
                self.set_gauge("admin_locked", 0 if bool(sec.is_admin()) else 1)
            except Exception:
                pass

    def _emit_if_changed(self, subsystem: Subsystem, old_status: Optional[HealthStatus], new_res: HealthCheckResult, *, trace_id: str) -> None:
        if old_status is None:
            return
        if old_status == new_res.status:
            return
        self._event_writer.emit(
            HealthEvent(
                trace_id=trace_id,
                event_type="health_change",
                subsystem=subsystem,
                old_status=old_status,
                new_status=new_res.status,
                message=new_res.message,
                details={"remediation": new_res.remediation},
            )
        )
        # Publish to internal event bus if attached.
        try:
            bus = self._deps.get("event_bus")
            if bus is not None:
                from jarvis.core.events.models import BaseEvent, EventSeverity, SourceSubsystem

                bus.publish_nowait(
                    BaseEvent(
                        event_type="telemetry.health_change",
                        trace_id=trace_id,
                        source_subsystem=SourceSubsystem.telemetry,
                        severity=EventSeverity.WARN,
                        payload={"subsystem": subsystem.value, "from": old_status.value, "to": new_res.status.value, "message": new_res.message},
                    )
                )
        except Exception:
            pass

    def _build_checks(self) -> List[CheckSpec]:
        with self._lock:
            deps = dict(self._deps)
            web = self._web
            ui_last = self._ui_last_heartbeat

        checks: List[CheckSpec] = []

        cm = deps.get("config_manager")
        if cm is not None:
            checks.append(CheckSpec(Subsystem.config, lambda: ok(Subsystem.config, "config loaded", details={"version": getattr(cm.get().app, "config_version", None)}), timeout_seconds=0.3))

        ss = deps.get("secure_store")
        if ss is not None:
            def chk_secure():
                st = ss.status()
                mode = getattr(st, "mode", None)
                mode_s = mode.value if hasattr(mode, "value") else str(mode)
                if mode_s == "READY":
                    return ok(Subsystem.secure_store, "secure store ready", details={"mode": mode_s})
                if mode_s == "READ_ONLY":
                    return degraded(Subsystem.secure_store, "secure store read-only", details={"mode": mode_s}, remediation="Disable read-only mode in config/security.json.")
                if mode_s == "KEY_MISSING":
                    return degraded(Subsystem.secure_store, "USB key missing", details={"mode": mode_s}, remediation="Insert USB key and ensure path matches config/security.json.")
                if mode_s in {"STORE_CORRUPT", "KEY_MISMATCH"}:
                    return down(Subsystem.secure_store, "secure store unavailable", details={"mode": mode_s}, remediation="Restore secure store from backups or use correct USB key.")
                return degraded(Subsystem.secure_store, "secure store not ready", details={"mode": mode_s})

            checks.append(CheckSpec(Subsystem.secure_store, chk_secure, timeout_seconds=0.8))

        runtime = deps.get("runtime")
        if runtime is not None:
            checks.append(CheckSpec(Subsystem.state_machine, lambda: ok(Subsystem.state_machine, "runtime responding", details=runtime.get_status()), timeout_seconds=0.5))

        dispatcher = deps.get("dispatcher")
        if dispatcher is not None:
            checks.append(CheckSpec(Subsystem.dispatcher, lambda: ok(Subsystem.dispatcher, "dispatcher ready"), timeout_seconds=0.2))

        jarvis_app = deps.get("jarvis_app")
        if jarvis_app is not None:
            checks.append(CheckSpec(Subsystem.intent_router, lambda: ok(Subsystem.intent_router, "routers ready", details={"threshold": getattr(jarvis_app, "threshold", None)}), timeout_seconds=0.2))

        llm = deps.get("llm_lifecycle")
        if llm is not None:
            def chk_llm():
                st = llm.get_status()
                roles = (st.get("roles") or {}) if isinstance(st, dict) else {}
                chat = roles.get("chat") or {}
                if not st.get("enabled", False):
                    return degraded(Subsystem.llm, "LLM disabled", details={"enabled": False})
                if isinstance(chat, dict) and chat.get("disabled"):
                    return down(Subsystem.llm, "LLM disabled by watchdog", details=telemetry_redact(chat), remediation="Check LLM backend (llamacpp model or Ollama server) and restart Jarvis.")
                if isinstance(chat, dict) and chat.get("last_error"):
                    return degraded(Subsystem.llm, "LLM errors", details={"last_error": chat.get("last_error")}, remediation="Ensure local LLM server is reachable.")
                return ok(Subsystem.llm, "LLM lifecycle ok", details={"chat_loaded": bool(chat.get("loaded"))})

            checks.append(CheckSpec(Subsystem.llm, chk_llm, timeout_seconds=0.8))

        jm = deps.get("job_manager")
        if jm is not None:
            def chk_jobs():
                try:
                    counts = jm.get_counts() if hasattr(jm, "get_counts") else _job_counts_fallback(jm)
                except Exception:
                    counts = {"queued": None, "running": None}
                return ok(Subsystem.jobs, "jobs ok", details=counts)

            checks.append(CheckSpec(Subsystem.jobs, chk_jobs, timeout_seconds=0.8))

        # Web server (thread info set by app)
        if web is not None:
            def chk_web():
                if not web.enabled:
                    return unknown(Subsystem.web, "web disabled", details={"enabled": False})
                if not web.thread_alive:
                    return degraded(Subsystem.web, "web thread not alive", details={"enabled": True}, remediation="Restart Jarvis.")
                return ok(Subsystem.web, "web running", details={"bind_host": web.bind_host, "port": web.port, "allow_remote": web.allow_remote})

            checks.append(CheckSpec(Subsystem.web, chk_web, timeout_seconds=0.2))

        # Voice/tts (runtime reports)
        if runtime is not None:
            def chk_voice():
                v = runtime.get_voice_status()
                if not v.get("available", False) and v.get("voice_enabled", False):
                    return degraded(Subsystem.voice, "voice enabled but unavailable", details=v, remediation="Check voice config/models.")
                return ok(Subsystem.voice, "voice ok", details=v) if v.get("available", False) else unknown(Subsystem.voice, "voice unavailable", details=v)

            checks.append(CheckSpec(Subsystem.voice, chk_voice, timeout_seconds=0.4))

        if runtime is not None:
            def chk_tts():
                v = runtime.get_voice_status()
                if v.get("tts_enabled", False):
                    return ok(Subsystem.tts, "tts enabled", details={"enabled": True})
                return degraded(Subsystem.tts, "tts disabled", details={"enabled": False})

            checks.append(CheckSpec(Subsystem.tts, chk_tts, timeout_seconds=0.4))

        # UI heartbeat
        def chk_ui():
            if ui_last is None:
                return unknown(Subsystem.ui, "ui not running", details={"running": False})
            age = time.time() - float(ui_last)
            if age > 3.0 * float(self.cfg.poll_interval_seconds):
                return degraded(Subsystem.ui, "ui heartbeat stale", details={"age_seconds": age}, remediation="UI may be unresponsive.")
            return ok(Subsystem.ui, "ui ok", details={"age_seconds": age})

        checks.append(CheckSpec(Subsystem.ui, chk_ui, timeout_seconds=0.2))

        return checks

    def _sample_resources(self) -> None:
        t0 = time.time()
        r = self._sampler.sample()
        with self._lock:
            self._last_resources = r
        self.record_latency("resource_sample_latency_ms", (time.time() - t0) * 1000.0)
        self._emit_resource_alerts(r)

    def _emit_resource_alerts(self, r: ResourceSample) -> None:
        th = self.cfg.thresholds or {}
        cpu_w = float(th.get("cpu_warn_percent", 85))
        ram_w = float(th.get("ram_warn_percent", 85))
        disk_w = float(th.get("disk_warn_percent_used", 90))
        gpu_w = float(th.get("gpu_vram_warn_percent", 90))

        def alert(msg: str, details: Dict[str, Any]) -> None:
            self._event_writer.emit(HealthEvent(trace_id="telemetry", event_type="resource_alert", message=msg, details=telemetry_redact(details)))

        if r.cpu_system_percent is not None and r.cpu_system_percent >= cpu_w:
            alert("High CPU usage", {"cpu_system_percent": r.cpu_system_percent, "threshold": cpu_w})
        if r.ram_system_percent is not None and r.ram_system_percent >= ram_w:
            alert("High RAM usage", {"ram_system_percent": r.ram_system_percent, "threshold": ram_w})
        if r.disk_root_percent_used is not None and r.disk_root_percent_used >= disk_w:
            alert("Disk usage high (root)", {"disk_root_percent_used": r.disk_root_percent_used, "threshold": disk_w})
        if r.disk_logs_percent_used is not None and r.disk_logs_percent_used >= disk_w:
            alert("Disk usage high (logs)", {"disk_logs_percent_used": r.disk_logs_percent_used, "threshold": disk_w})
        # GPU VRAM: if we have gpus list
        g = r.gpu or {}
        if isinstance(g, dict) and g.get("status") == "ok":
            for gpu in (g.get("gpus") or []):
                try:
                    pct = float(gpu.get("vram_percent"))
                except Exception:
                    pct = None
                if pct is not None and pct >= gpu_w:
                    alert("GPU VRAM usage high", {"index": gpu.get("index"), "name": gpu.get("name"), "vram_percent": pct, "threshold": gpu_w})

    def _cleanup_retention(self) -> None:
        # local cleanup: remove telemetry jsonl older than retention_days
        keep_days = max(1, int(self.cfg.retention_days))
        cutoff = time.time() - float(keep_days * 86400)
        base = os.path.join("logs", "telemetry")
        if not os.path.isdir(base):
            return
        try:
            for name in os.listdir(base):
                if not name.endswith(".jsonl"):
                    continue
                path = os.path.join(base, name)
                try:
                    if os.path.getmtime(path) < cutoff:
                        os.remove(path)
                except OSError:
                    continue
        except Exception:
            return


def _job_counts_fallback(jm: Any) -> Dict[str, Any]:
    # derive from list_jobs if no explicit counts method
    try:
        jobs = jm.list_jobs()
    except Exception:
        return {"queued": None, "running": None}
    queued = 0
    running = 0
    for j in jobs:
        st = getattr(j, "status", None)
        sv = st.value if hasattr(st, "value") else str(st)
        if sv == "QUEUED":
            queued += 1
        if sv == "RUNNING":
            running += 1
    return {"queued": queued, "running": running, "total": len(jobs)}

