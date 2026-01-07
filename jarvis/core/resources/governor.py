from __future__ import annotations

import threading
import time
from typing import Any, Callable, Dict, List, Optional

from jarvis.core.resources.admission import AdmissionGate, DelayConfig
from jarvis.core.resources.models import (
    AdmissionAction,
    AdmissionDecision,
    ResourceGovernorConfig,
    ResourceSnapshot,
)
from jarvis.core.resources.policies import decide_over_budget


class ResourceGovernor:
    """
    Resource Governor:
    - periodic sampling (thread)
    - over-budget detection
    - admission control for heavy operations
    - concurrency throttling via semaphores
    - safe-mode enter/exit under sustained pressure
    """

    def __init__(
        self,
        *,
        cfg: ResourceGovernorConfig,
        sampler: Optional[Callable[[], ResourceSnapshot]] = None,
        telemetry: Any = None,
        event_bus: Any = None,
        runtime_state: Any = None,
        llm_lifecycle: Any = None,
        logger=None,
        now: Callable[[], float] = time.time,
        sleep: Callable[[float], None] = time.sleep,
    ):
        self.cfg = cfg
        self._sampler = sampler
        self.telemetry = telemetry
        self.event_bus = event_bus
        self.runtime_state = runtime_state
        self.llm_lifecycle = llm_lifecycle
        self.logger = logger
        self._now = now
        self._sleep = sleep
        self._gate = AdmissionGate(now=now, sleep=sleep)

        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._loop, name="resource-governor", daemon=True)

        # concurrency throttles
        self._heavy_jobs_sem = threading.Semaphore(max(0, int(cfg.throttles.max_concurrent_heavy_jobs)))
        self._llm_sem = threading.Semaphore(max(0, int(cfg.throttles.max_concurrent_llm_requests)))

        self._last_snapshot = ResourceSnapshot()
        self._consecutive_violations = 0
        self._over_budget_since: Optional[float] = None
        self._safe_mode = False
        self._safe_mode_forced: Optional[bool] = None
        self._stable_since: Optional[float] = None

        if bool(cfg.enabled):
            self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread.is_alive():
            self._thread.join(timeout=2.0)

    # ---- UI/CLI surfaces ----
    def get_status(self) -> Dict[str, Any]:
        with self._lock:
            snap = self._last_snapshot
            return {
                "enabled": bool(self.cfg.enabled),
                "safe_mode": bool(self._safe_mode),
                "forced_safe_mode": self._safe_mode_forced,
                "consecutive_violations": int(self._consecutive_violations),
                "snapshot": snap.public_dict(),
                "budgets": self.cfg.budgets.model_dump(),
                "policy": self.cfg.policies.model_dump(),
                "throttles": self.cfg.throttles.model_dump(),
            }

    def get_snapshot(self) -> Dict[str, Any]:
        with self._lock:
            return self._last_snapshot.public_dict()

    def set_forced_safe_mode(self, enabled: Optional[bool], *, reason: str = "manual") -> None:
        with self._lock:
            self._safe_mode_forced = enabled
        self._apply_safe_mode_state(reason=reason)

    def safe_mode_active(self) -> bool:
        with self._lock:
            return bool(self._safe_mode)

    def is_over_budget(self) -> bool:
        snap = self._get_snapshot_locked()
        return bool(self._over_budget_reasons(snap))

    def over_budget_reasons(self) -> list[str]:
        snap = self._get_snapshot_locked()
        return list(self._over_budget_reasons(snap))

    # ---- admission control ----
    def admit(
        self,
        *,
        operation: str,
        trace_id: str,
        required_caps: Optional[List[str]] = None,
        allow_delay: bool = False,
        wants_llm_slot: bool = False,
        wants_heavy_job_slot: bool = False,
    ) -> AdmissionDecision:
        if not bool(self.cfg.enabled):
            return AdmissionDecision(allowed=True, action=AdmissionAction.ALLOW, reasons=["Governor disabled."], snapshot=self.get_snapshot())

        def _evaluate_once() -> tuple[AdmissionDecision, ResourceSnapshot]:
            snap = self._get_snapshot_locked()
            reasons = self._over_budget_reasons(snap)
            if reasons:
                dec = decide_over_budget(self.cfg, snapshot=snap, reasons=reasons)
                return dec, snap
            # Under budget -> allow (but may still throttle concurrency)
            return AdmissionDecision(allowed=True, action=AdmissionAction.ALLOW, reasons=["Under budget."], snapshot=snap.public_dict()), snap

        dec, snap = _evaluate_once()

        # Concurrency throttles (LLM / heavy jobs) are enforced even if under budget.
        if dec.allowed:
            if wants_llm_slot and not self._try_acquire(self._llm_sem):
                dec = AdmissionDecision(
                    allowed=False,
                    action=AdmissionAction.THROTTLE,
                    delay_seconds=min(1.0, float(self.cfg.policies.max_delay_seconds)),
                    reasons=["LLM concurrency limit reached."],
                    remediation="Too many LLM requests in flight. Try again shortly.",
                    snapshot=snap.public_dict(),
                )
            if wants_heavy_job_slot and not self._try_acquire(self._heavy_jobs_sem):
                dec = AdmissionDecision(
                    allowed=False,
                    action=AdmissionAction.THROTTLE,
                    delay_seconds=min(1.0, float(self.cfg.policies.max_delay_seconds)),
                    reasons=["Heavy job concurrency limit reached."],
                    remediation="Too many heavy jobs running. Try again shortly.",
                    snapshot=snap.public_dict(),
                )

        # DELAY behavior (optional): retry until max_delay
        if allow_delay and dec.action == AdmissionAction.DELAY:
            dec = self._gate.maybe_delay(
                decision=dec,
                cfg=DelayConfig(max_delay_seconds=float(self.cfg.policies.max_delay_seconds)),
                recheck=lambda: _evaluate_once(),
            )

        # Update violation counters and safe mode transitions
        self._update_pressure_state(dec, snap, trace_id=trace_id, operation=operation)
        self._log_decision(trace_id=trace_id, operation=operation, decision=dec)
        return dec

    def release_llm_slot(self) -> None:
        self._release(self._llm_sem)

    def release_heavy_job_slot(self) -> None:
        self._release(self._heavy_jobs_sem)

    # ---- internals ----
    def _loop(self) -> None:
        interval = max(0.2, float(self.cfg.sample_interval_seconds))
        while not self._stop.is_set():
            try:
                snap = self._sample()
                with self._lock:
                    self._last_snapshot = snap
                # passive pressure handling: reclaim LLM under pressure
                self._maybe_reclaim_llm(snap)
                # metrics/events
                if self.telemetry is not None:
                    try:
                        if snap.cpu_system_percent is not None:
                            self.telemetry.set_gauge("resource_cpu_system_percent", float(snap.cpu_system_percent))
                        if snap.ram_system_percent is not None:
                            self.telemetry.set_gauge("resource_ram_system_percent", float(snap.ram_system_percent))
                    except Exception:
                        pass
            except Exception:
                pass
            self._sleep(interval)

    def _sample(self) -> ResourceSnapshot:
        if self._sampler is not None:
            return self._sampler()
        from jarvis.core.resources.sampler import ResourceSampler

        # GPU NVML is optional; tie to telemetry config if present
        enable_nvml = True
        try:
            if self.telemetry is not None and hasattr(self.telemetry, "cfg"):
                enable_nvml = bool(getattr(getattr(self.telemetry, "cfg"), "gpu", {}).get("enable_nvml", True))
        except Exception:
            enable_nvml = True
        return ResourceSampler(root_path=".", logs_path="logs", enable_nvml=enable_nvml).sample()

    def _get_snapshot_locked(self) -> ResourceSnapshot:
        with self._lock:
            return ResourceSnapshot.model_validate(self._last_snapshot.model_dump())

    def _over_budget_reasons(self, snap: ResourceSnapshot) -> List[str]:
        b = self.cfg.budgets
        reasons: List[str] = []
        if snap.cpu_system_percent is not None and snap.cpu_system_percent >= float(b.cpu_max_percent):
            reasons.append(f"CPU {snap.cpu_system_percent:.0f}% >= {b.cpu_max_percent:.0f}%")
        if snap.ram_system_percent is not None and snap.ram_system_percent >= float(b.ram_max_percent):
            reasons.append(f"RAM {snap.ram_system_percent:.0f}% >= {b.ram_max_percent:.0f}%")
        if snap.ram_process_rss_bytes is not None:
            rss_mb = float(snap.ram_process_rss_bytes) / (1024 * 1024)
            if rss_mb >= float(b.process_ram_max_mb):
                reasons.append(f"Process RSS {rss_mb:.0f}MB >= {b.process_ram_max_mb}MB")
        min_free = float(b.disk_min_free_gb) * (1024 * 1024 * 1024)
        for label, free in [("disk_root", snap.disk_root_free_bytes), ("disk_logs", snap.disk_logs_free_bytes)]:
            if free is not None and float(free) < min_free:
                reasons.append(f"{label} free < {b.disk_min_free_gb:.1f}GB")
        if snap.gpu_status == "ok" and snap.gpu_vram_max_percent is not None and snap.gpu_vram_max_percent >= float(b.gpu_vram_max_percent):
            reasons.append(f"GPU VRAM {snap.gpu_vram_max_percent:.0f}% >= {b.gpu_vram_max_percent:.0f}%")
        return reasons

    def _update_pressure_state(self, dec: AdmissionDecision, snap: ResourceSnapshot, *, trace_id: str, operation: str) -> None:
        over = (dec.action in {AdmissionAction.DENY, AdmissionAction.DELAY, AdmissionAction.THROTTLE}) and any("CPU" in r or "RAM" in r or "disk" in r.lower() or "GPU" in r for r in (dec.reasons or []))
        now = self._now()
        changed = False
        with self._lock:
            if over:
                self._consecutive_violations += 1
                self._stable_since = None
                if self._over_budget_since is None:
                    self._over_budget_since = now
                if (self._safe_mode_forced is None) and (not self._safe_mode) and self._consecutive_violations >= int(self.cfg.safe_mode.enter_after_consecutive_violations):
                    self._safe_mode = True
                    changed = True
            else:
                self._consecutive_violations = 0
                self._over_budget_since = None
                if self._stable_since is None:
                    self._stable_since = now
                if (self._safe_mode_forced is None) and self._safe_mode and self._stable_since is not None:
                    if (now - self._stable_since) >= float(self.cfg.safe_mode.exit_after_seconds_stable):
                        self._safe_mode = False
                        changed = True

        if changed:
            self._apply_safe_mode_state(reason=f"resource_pressure:{operation}", trace_id=trace_id)

        if over and self.telemetry is not None:
            try:
                self.telemetry.increment_counter("resource_violations_total", 1)
            except Exception:
                pass

    def _apply_safe_mode_state(self, *, reason: str, trace_id: str = "resource") -> None:
        with self._lock:
            if self._safe_mode_forced is not None:
                self._safe_mode = bool(self._safe_mode_forced)
            active = bool(self._safe_mode)

        if self.runtime_state is not None:
            try:
                self.runtime_state.set_safe_mode_active(active, reason=reason)
            except Exception:
                pass
        if self.event_bus is not None:
            try:
                from jarvis.core.events.models import BaseEvent, EventSeverity, SourceSubsystem

                self.event_bus.publish_nowait(
                    BaseEvent(
                        event_type="resource.safe_mode_entered" if active else "resource.safe_mode_exited",
                        trace_id=trace_id,
                        source_subsystem=SourceSubsystem.telemetry,
                        severity=EventSeverity.WARN if active else EventSeverity.INFO,
                        payload={"active": active, "reason": reason},
                    )
                )
            except Exception:
                pass

    def _maybe_reclaim_llm(self, snap: ResourceSnapshot) -> None:
        if self.llm_lifecycle is None:
            return
        # If RAM or VRAM is high, try to unload chat if idle; else unload all.
        b = self.cfg.budgets
        ram_high = (snap.ram_system_percent is not None) and (snap.ram_system_percent >= float(b.ram_max_percent))
        vram_high = (snap.gpu_status == "ok") and (snap.gpu_vram_max_percent is not None) and (snap.gpu_vram_max_percent >= float(b.gpu_vram_max_percent))
        rss_high = False
        if snap.ram_process_rss_bytes is not None:
            rss_mb = float(snap.ram_process_rss_bytes) / (1024 * 1024)
            rss_high = rss_mb >= float(b.process_ram_max_mb)
        if not (ram_high or vram_high or rss_high):
            return
        try:
            st = self.llm_lifecycle.get_status() or {}
            roles = (st.get("roles") or {})
            chat = roles.get("chat") or {}
            if bool(chat.get("loaded")) and (chat.get("idle_seconds") is not None) and float(chat.get("idle_seconds") or 0) >= 1.0:
                self.llm_lifecycle.unload_role("chat", reason="resource_pressure", trace_id="resource")
            else:
                self.llm_lifecycle.unload_all(reason="resource_pressure")
            if self.event_bus is not None:
                from jarvis.core.events.models import BaseEvent, EventSeverity, SourceSubsystem

                self.event_bus.publish_nowait(
                    BaseEvent(
                        event_type="resource.reclaimed",
                        trace_id="resource",
                        source_subsystem=SourceSubsystem.llm,
                        severity=EventSeverity.WARN,
                        payload={"reason": "resource_pressure"},
                    )
                )
        except Exception:
            return

    def _log_decision(self, *, trace_id: str, operation: str, decision: AdmissionDecision) -> None:
        if self.event_bus is not None:
            try:
                from jarvis.core.events.models import BaseEvent, EventSeverity, SourceSubsystem

                sev = EventSeverity.INFO if decision.allowed else EventSeverity.WARN
                self.event_bus.publish_nowait(
                    BaseEvent(
                        event_type="resource.admission_denied" if not decision.allowed else "resource.admission_allowed",
                        trace_id=trace_id,
                        source_subsystem=SourceSubsystem.dispatcher,
                        severity=sev,
                        payload={"operation": operation, "allowed": decision.allowed, "action": decision.action.value, "reasons": decision.reasons, "snapshot": decision.snapshot},
                    )
                )
            except Exception:
                pass
        if self.telemetry is not None:
            try:
                self.telemetry.increment_counter(
                    "resource_admission_total",
                    1,
                    tags={"operation": operation, "action": decision.action.value, "allowed": str(bool(decision.allowed)).lower()},
                )
            except Exception:
                pass

    @staticmethod
    def _try_acquire(sem: threading.Semaphore) -> bool:
        try:
            return bool(sem.acquire(blocking=False))
        except Exception:
            return True

    @staticmethod
    def _release(sem: threading.Semaphore) -> None:
        try:
            sem.release()
        except Exception:
            pass

