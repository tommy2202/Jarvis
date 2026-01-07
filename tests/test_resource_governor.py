from __future__ import annotations

import time

from jarvis.core.resources.governor import ResourceGovernor
from jarvis.core.resources.models import (
    AdmissionAction,
    BudgetConfig,
    PolicyConfig,
    ResourceGovernorConfig,
    ResourceSnapshot,
    SafeModeConfig,
    ThrottleConfig,
)


def _mk_cfg(on_over_budget: str = "DENY") -> ResourceGovernorConfig:
    return ResourceGovernorConfig(
        enabled=True,
        sample_interval_seconds=9999,
        budgets=BudgetConfig(cpu_max_percent=50, ram_max_percent=50, process_ram_max_mb=100, disk_min_free_gb=0.1, gpu_vram_max_percent=50),
        policies=PolicyConfig(on_over_budget=on_over_budget, cooldown_seconds=0.0, max_delay_seconds=1.0),
        throttles=ThrottleConfig(max_concurrent_heavy_jobs=1, max_concurrent_llm_requests=1, max_total_jobs=2),
        safe_mode=SafeModeConfig(enter_after_consecutive_violations=2, exit_after_seconds_stable=1.0),
    )


def test_admission_allows_under_budget(monkeypatch):
    snap = ResourceSnapshot(cpu_system_percent=10, ram_system_percent=10, ram_process_rss_bytes=10 * 1024 * 1024, disk_root_free_bytes=10**10, disk_logs_free_bytes=10**10)
    gov = ResourceGovernor(cfg=_mk_cfg(), sampler=lambda: snap)
    # overwrite last snapshot deterministically
    with gov._lock:
        gov._last_snapshot = snap
    dec = gov.admit(operation="intent.execute", trace_id="t1")
    assert dec.allowed is True
    assert dec.action == AdmissionAction.ALLOW


def test_admission_denies_over_budget(monkeypatch):
    snap = ResourceSnapshot(cpu_system_percent=99, ram_system_percent=10, ram_process_rss_bytes=10 * 1024 * 1024, disk_root_free_bytes=10**10, disk_logs_free_bytes=10**10)
    gov = ResourceGovernor(cfg=_mk_cfg(on_over_budget="DENY"), sampler=lambda: snap)
    with gov._lock:
        gov._last_snapshot = snap
    dec = gov.admit(operation="llm.request", trace_id="t2")
    assert dec.allowed is False
    assert dec.action in {AdmissionAction.DENY, AdmissionAction.THROTTLE, AdmissionAction.DELAY}


def test_safe_mode_enters_after_consecutive_violations(monkeypatch):
    # Two consecutive over-budget admissions should enter safe mode (cfg enter_after_consecutive_violations=2)
    snap_over = ResourceSnapshot(cpu_system_percent=99, ram_system_percent=99, ram_process_rss_bytes=999 * 1024 * 1024, disk_root_free_bytes=1, disk_logs_free_bytes=1)
    gov = ResourceGovernor(cfg=_mk_cfg(on_over_budget="DENY"), sampler=lambda: snap_over)
    with gov._lock:
        gov._last_snapshot = snap_over
    _ = gov.admit(operation="intent.execute", trace_id="t3")
    _ = gov.admit(operation="intent.execute", trace_id="t4")
    assert gov.safe_mode_active() is True


def test_safe_mode_exits_after_stable_window(monkeypatch):
    now = [1000.0]

    def _now():
        return now[0]

    snap_over = ResourceSnapshot(cpu_system_percent=99, ram_system_percent=99, ram_process_rss_bytes=999 * 1024 * 1024, disk_root_free_bytes=1, disk_logs_free_bytes=1)
    snap_ok = ResourceSnapshot(cpu_system_percent=10, ram_system_percent=10, ram_process_rss_bytes=10 * 1024 * 1024, disk_root_free_bytes=10**10, disk_logs_free_bytes=10**10)

    cur = {"snap": snap_over}

    gov = ResourceGovernor(cfg=_mk_cfg(on_over_budget="DENY"), sampler=lambda: cur["snap"], now=_now, sleep=lambda _s: None)
    with gov._lock:
        gov._last_snapshot = snap_over
    _ = gov.admit(operation="intent.execute", trace_id="t5")
    _ = gov.admit(operation="intent.execute", trace_id="t6")
    assert gov.safe_mode_active() is True

    # become stable
    cur["snap"] = snap_ok
    with gov._lock:
        gov._last_snapshot = snap_ok
    now[0] += 2.0  # > exit_after_seconds_stable
    _ = gov.admit(operation="intent.execute", trace_id="t7")
    assert gov.safe_mode_active() is False


def test_llm_reclaim_called_under_pressure(monkeypatch):
    snap_over = ResourceSnapshot(cpu_system_percent=10, ram_system_percent=99, ram_process_rss_bytes=999 * 1024 * 1024, disk_root_free_bytes=10**10, disk_logs_free_bytes=10**10, gpu_status="unavailable")

    class FakeLLM:
        def __init__(self):
            self.unloaded = []

        def get_status(self):
            return {"roles": {"chat": {"loaded": True, "idle_seconds": 10}}}

        def unload_role(self, role, reason, trace_id):
            self.unloaded.append((role, reason))

        def unload_all(self, reason):
            self.unloaded.append(("all", reason))

    llm = FakeLLM()
    gov = ResourceGovernor(cfg=_mk_cfg(on_over_budget="DENY"), sampler=lambda: snap_over, llm_lifecycle=llm)
    gov._maybe_reclaim_llm(snap_over)
    assert llm.unloaded

