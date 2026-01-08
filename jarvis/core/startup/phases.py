from __future__ import annotations

import os
from typing import Any, Dict, List, Optional

from jarvis.core.config.migrations.runner import latest_version
from jarvis.core.startup.checks import check_clock_sanity, check_dir_writable, check_os_windows, check_python_version, fingerprint_files
from jarvis.core.startup.models import CheckResult, CheckStatus, PhaseResult, Severity


def phase0_bootstrap_integrity(*, root_dir: str, logs_dir: str) -> PhaseResult:
    checks: List[CheckResult] = []
    checks.append(check_python_version())
    checks.append(check_os_windows())
    checks.append(check_dir_writable(root_dir, "project_dir_writable"))
    checks.append(check_dir_writable(logs_dir, "logs_dir_writable"))
    checks.append(check_clock_sanity())
    status = _phase_status(checks, fail_if_any_failed=True)
    return PhaseResult(phase_id=0, name="Bootstrap Integrity", status=status, checks=checks)


def phase1_config_validation(*, config_manager) -> tuple[PhaseResult, Dict[str, str]]:
    checks: List[CheckResult] = []
    fingerprints: Dict[str, str] = {}
    try:
        config_manager.validate()
        checks.append(CheckResult(check_id="config.validate", status=CheckStatus.OK, message="Config validated."))
    except Exception as e:  # noqa: BLE001
        checks.append(CheckResult(check_id="config.validate", status=CheckStatus.FAILED, message="Config validation failed.", remediation=str(e), severity=Severity.CRITICAL))

    try:
        cfg = config_manager.get()
        cur = int(getattr(cfg.app, "config_version", 0) or 0)
        latest = int(latest_version())
        if cur >= latest:
            checks.append(CheckResult(check_id="config.migrations", status=CheckStatus.OK, message=f"Migrations OK (version={cur})."))
        else:
            checks.append(CheckResult(check_id="config.migrations", status=CheckStatus.FAILED, message=f"Migrations incomplete (version={cur} < {latest}).", remediation="Re-run Jarvis to apply migrations or fix config/app.json.", severity=Severity.CRITICAL))
    except Exception as e:
        checks.append(CheckResult(check_id="config.migrations", status=CheckStatus.DEGRADED, message="Unable to verify migrations.", remediation=str(e), severity=Severity.WARN))

    try:
        cfg_dir = getattr(config_manager.fs, "config_dir", "config")
        fingerprints = fingerprint_files(cfg_dir)
        checks.append(CheckResult(check_id="config.fingerprints", status=CheckStatus.OK, message=f"Fingerprints computed for {len(fingerprints)} files."))
    except Exception as e:
        checks.append(CheckResult(check_id="config.fingerprints", status=CheckStatus.DEGRADED, message="Unable to compute config fingerprints.", remediation=str(e), severity=Severity.WARN))

    status = _phase_status(checks, fail_if_any_failed=True)
    return PhaseResult(phase_id=1, name="Configuration Validation", status=status, checks=checks), fingerprints


def phase2_secure_store(*, secure_store) -> PhaseResult:
    checks: List[CheckResult] = []
    try:
        st = secure_store.status()
        mode = st.mode.value if hasattr(st.mode, "value") else str(st.mode)
        if mode == "READY":
            checks.append(CheckResult(check_id="secure_store", status=CheckStatus.OK, message="Secure store READY."))
        elif mode == "KEY_MISSING":
            checks.append(CheckResult(check_id="secure_store", status=CheckStatus.DEGRADED, message="USB key missing (secure features disabled).", remediation=st.next_steps, severity=Severity.WARN))
        elif mode in {"READ_ONLY"}:
            checks.append(CheckResult(check_id="secure_store", status=CheckStatus.DEGRADED, message="Secure store read-only.", remediation=st.next_steps, severity=Severity.WARN))
        elif mode in {"STORE_CORRUPT", "KEY_MISMATCH"}:
            checks.append(CheckResult(check_id="secure_store", status=CheckStatus.FAILED, message=f"Secure store error: {mode}.", remediation=st.next_steps, severity=Severity.CRITICAL))
        else:
            checks.append(CheckResult(check_id="secure_store", status=CheckStatus.DEGRADED, message=f"Secure store: {mode}.", remediation=st.next_steps, severity=Severity.WARN))
    except Exception as e:  # noqa: BLE001
        checks.append(CheckResult(check_id="secure_store", status=CheckStatus.FAILED, message="Secure store check failed.", remediation=str(e), severity=Severity.CRITICAL))

    # failure rule: KEY_MISMATCH / STORE_CORRUPT must BLOCK startup (phase FAILED)
    status = _phase_status(checks, fail_if_any_failed=True)
    return PhaseResult(phase_id=2, name="Secure Store & USB Key", status=status, checks=checks)


def phase3_runtime_state(*, runtime_state) -> PhaseResult:
    checks: List[CheckResult] = []
    try:
        st = runtime_state.load()
        checks.append(CheckResult(check_id="runtime_state.load", status=CheckStatus.OK, message="Runtime state loaded."))
        # dirty shutdown detection
        snap = runtime_state.get_snapshot()
        dirty = bool((snap.get("crash") or {}).get("dirty_shutdown_detected", False))
        if dirty:
            checks.append(CheckResult(check_id="runtime_state.dirty_shutdown", status=CheckStatus.DEGRADED, message="Dirty shutdown detected (starting degraded).", remediation="Review logs/ops.jsonl and runtime/state.json.", severity=Severity.WARN))
        else:
            checks.append(CheckResult(check_id="runtime_state.dirty_shutdown", status=CheckStatus.OK, message="No dirty shutdown marker."))
        # ensure admin locked
        if bool((snap.get("security") or {}).get("admin_locked", True)) is True:
            checks.append(CheckResult(check_id="runtime_state.admin_locked", status=CheckStatus.OK, message="Admin locked on startup."))
        else:
            checks.append(CheckResult(check_id="runtime_state.admin_locked", status=CheckStatus.DEGRADED, message="Admin was not locked (forced lock).", severity=Severity.WARN))
    except Exception as e:
        checks.append(CheckResult(check_id="runtime_state.load", status=CheckStatus.FAILED, message="Failed to load runtime state.", remediation=str(e), severity=Severity.CRITICAL))

    status = _phase_status(checks, fail_if_any_failed=True)
    return PhaseResult(phase_id=3, name="Runtime State Recovery", status=status, checks=checks)


def phase4_core_readiness(*, capability_ok: bool, event_bus_ok: bool, telemetry_ok: bool, job_manager_ok: bool, error_policy_ok: bool, runtime_ok: bool) -> PhaseResult:
    checks: List[CheckResult] = []
    checks.append(CheckResult(check_id="capabilities", status=CheckStatus.OK if capability_ok else CheckStatus.FAILED, message="Capability bus ready." if capability_ok else "Capability bus missing/invalid.", severity=Severity.CRITICAL if not capability_ok else Severity.INFO))
    checks.append(CheckResult(check_id="event_bus", status=CheckStatus.OK if event_bus_ok else CheckStatus.FAILED, message="Event bus ready." if event_bus_ok else "Event bus failed to initialize.", severity=Severity.CRITICAL if not event_bus_ok else Severity.INFO))
    checks.append(CheckResult(check_id="telemetry", status=CheckStatus.OK if telemetry_ok else CheckStatus.FAILED, message="Telemetry running." if telemetry_ok else "Telemetry not running.", severity=Severity.CRITICAL if not telemetry_ok else Severity.INFO))
    checks.append(CheckResult(check_id="jobs", status=CheckStatus.OK if job_manager_ok else CheckStatus.FAILED, message="Job manager ready." if job_manager_ok else "Job manager not ready.", severity=Severity.CRITICAL if not job_manager_ok else Severity.INFO))
    checks.append(CheckResult(check_id="recovery_policy", status=CheckStatus.OK if error_policy_ok else CheckStatus.FAILED, message="Error handling/recovery ready." if error_policy_ok else "Error handling/recovery missing.", severity=Severity.CRITICAL if not error_policy_ok else Severity.INFO))
    checks.append(CheckResult(check_id="state_machine", status=CheckStatus.OK if runtime_ok else CheckStatus.FAILED, message="State machine instantiated." if runtime_ok else "State machine not ready.", severity=Severity.CRITICAL if not runtime_ok else Severity.INFO))
    status = _phase_status(checks, fail_if_any_failed=True)
    return PhaseResult(phase_id=4, name="Core Subsystem Readiness", status=status, checks=checks)


def phase5_optional_probing(*, cfg_obj) -> PhaseResult:
    checks: List[CheckResult] = []
    # Voice probing: do not require mic access.
    if bool(cfg_obj.voice.enabled) and bool(cfg_obj.state_machine.enable_voice):
        # Model paths sanity
        if not getattr(cfg_obj.models, "vosk_model_path", ""):
            checks.append(CheckResult(check_id="voice.vosk_model", status=CheckStatus.DEGRADED, message="Vosk model path not configured.", remediation="Set config/models.json.vosk_model_path.", severity=Severity.WARN))
        else:
            checks.append(CheckResult(check_id="voice.vosk_model", status=CheckStatus.OK, message="Vosk model path configured."))
    else:
        checks.append(CheckResult(check_id="voice", status=CheckStatus.OK, message="Voice disabled (skipping probe)."))

    # LLM probing: do not load models; just check config enabled.
    if bool(cfg_obj.llm.enabled):
        checks.append(CheckResult(check_id="llm.config", status=CheckStatus.OK, message="LLM enabled in config (backend probe deferred)."))
    else:
        checks.append(CheckResult(check_id="llm.config", status=CheckStatus.OK, message="LLM disabled."))

    # Web config sanity (binding validation happens in phase 6 too)
    checks.append(CheckResult(check_id="web.config", status=CheckStatus.OK, message=f"Web enabled={bool(cfg_obj.web.enabled)} allow_remote={bool(cfg_obj.web.allow_remote)}"))

    # UI availability
    try:
        import tkinter  # noqa: F401

        checks.append(CheckResult(check_id="ui.tk", status=CheckStatus.OK, message="Tkinter available."))
    except Exception as e:
        checks.append(CheckResult(check_id="ui.tk", status=CheckStatus.DEGRADED, message="Tkinter not available.", remediation=str(e), severity=Severity.WARN))

    status = _phase_status(checks, fail_if_any_failed=False)
    return PhaseResult(phase_id=5, name="Optional Subsystem Probing", status=status, checks=checks)


def phase6_policy_safety(*, cfg_obj, secure_store_mode: str, capabilities_cfg: Dict[str, Any]) -> PhaseResult:
    checks: List[CheckResult] = []
    # Remote access sanity
    if bool(cfg_obj.web.enabled) and bool(cfg_obj.web.allow_remote) and secure_store_mode != "READY":
        checks.append(
            CheckResult(
                check_id="web.remote_policy",
                status=CheckStatus.FAILED,
                message="Remote web enabled but secure store not READY.",
                remediation="Insert USB key and ensure secure store READY, or set web.allow_remote=false.",
                severity=Severity.CRITICAL,
            )
        )
    else:
        checks.append(CheckResult(check_id="web.remote_policy", status=CheckStatus.OK, message="Remote web policy OK."))

    # Ensure no high-sensitivity capability is default allow (fail-safe)
    try:
        caps = capabilities_cfg.get("capabilities") or {}
        risky = []
        for cid, c in caps.items():
            if str(c.get("sensitivity")) == "high" and str(c.get("default_policy")) == "allow":
                risky.append(cid)
        if risky:
            checks.append(CheckResult(check_id="caps.risky_defaults", status=CheckStatus.DEGRADED, message=f"High-sensitivity caps default allow: {risky}", remediation="Set default_policy=deny for high-sensitivity capabilities.", severity=Severity.WARN))
        else:
            checks.append(CheckResult(check_id="caps.risky_defaults", status=CheckStatus.OK, message="Capability defaults OK."))
    except Exception as e:
        checks.append(CheckResult(check_id="caps.risky_defaults", status=CheckStatus.DEGRADED, message="Unable to verify capability defaults.", remediation=str(e), severity=Severity.WARN))

    status = _phase_status(checks, fail_if_any_failed=False)
    return PhaseResult(phase_id=6, name="Policy & Safety Checks", status=status, checks=checks)


def _phase_status(checks: List[CheckResult], *, fail_if_any_failed: bool) -> CheckStatus:
    if fail_if_any_failed and any(c.status == CheckStatus.FAILED for c in checks):
        return CheckStatus.FAILED
    if any(c.status == CheckStatus.FAILED for c in checks):
        return CheckStatus.DEGRADED
    if any(c.status == CheckStatus.DEGRADED for c in checks):
        return CheckStatus.DEGRADED
    return CheckStatus.OK

