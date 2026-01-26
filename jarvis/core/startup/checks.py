from __future__ import annotations

import hashlib
import importlib
import os
import platform
import sys
import time
from typing import Any, Dict, Optional, Tuple

from jarvis.core.startup.models import CheckResult, CheckStatus, Severity


def check_python_version() -> CheckResult:
    if sys.version_info >= (3, 11):
        return CheckResult(check_id="python_version", status=CheckStatus.OK, message=f"Python {sys.version_info.major}.{sys.version_info.minor} OK")
    return CheckResult(check_id="python_version", status=CheckStatus.FAILED, message="Python >= 3.11 required.", remediation="Install Python 3.11+.", severity=Severity.CRITICAL)


def check_os_windows() -> CheckResult:
    sysname = platform.system()
    if sysname == "Windows":
        return CheckResult(check_id="os", status=CheckStatus.OK, message="Windows detected.")
    return CheckResult(check_id="os", status=CheckStatus.FAILED, message=f"Unsupported OS: {sysname}. Windows 10/11 required.", remediation="Run Jarvis on Windows 10/11.", severity=Severity.CRITICAL)


def check_dir_writable(path: str, check_id: str) -> CheckResult:
    try:
        os.makedirs(path, exist_ok=True)
        test = os.path.join(path, ".write_test")
        with open(test, "w", encoding="utf-8") as f:
            f.write("ok")
        os.remove(test)
        return CheckResult(check_id=check_id, status=CheckStatus.OK, message=f"Writable: {path}")
    except Exception as e:  # noqa: BLE001
        return CheckResult(check_id=check_id, status=CheckStatus.FAILED, message=f"Not writable: {path}", remediation=str(e), severity=Severity.CRITICAL)


def check_clock_sanity() -> CheckResult:
    # sanity: time after 2020-01-01
    if time.time() >= 1577836800:
        return CheckResult(check_id="clock", status=CheckStatus.OK, message="System clock looks sane.")
    return CheckResult(check_id="clock", status=CheckStatus.DEGRADED, message="System clock appears incorrect.", remediation="Fix system time to avoid TLS/log issues.", severity=Severity.WARN)


def fingerprint_files(dir_path: str) -> Dict[str, str]:
    out: Dict[str, str] = {}
    try:
        for name in sorted(os.listdir(dir_path)):
            if not name.endswith(".json"):
                continue
            p = os.path.join(dir_path, name)
            if not os.path.isfile(p):
                continue
            try:
                b = open(p, "rb").read()
                out[name] = hashlib.sha256(b).hexdigest()
            except Exception:
                continue
    except Exception:
        return {}
    return out


def hash_runtime_fingerprint(*parts: str) -> str:
    h = hashlib.sha256()
    for p in parts:
        h.update(p.encode("utf-8", errors="ignore"))
        h.update(b"\n")
    return h.hexdigest()


def check_dispatcher_capability_engine(dispatcher: Any) -> CheckResult:
    if dispatcher is None:
        return CheckResult(
            check_id="dispatcher.capability_engine",
            status=CheckStatus.FAILED,
            message="Dispatcher missing.",
            remediation="Initialize dispatcher before startup checks.",
            severity=Severity.CRITICAL,
        )
    if getattr(dispatcher, "capability_engine", None) is None:
        return CheckResult(
            check_id="dispatcher.capability_engine",
            status=CheckStatus.FAILED,
            message="Dispatcher missing capability engine.",
            remediation="Wire capability engine into dispatcher.",
            severity=Severity.CRITICAL,
        )
    return CheckResult(check_id="dispatcher.capability_engine", status=CheckStatus.OK, message="Dispatcher capability engine wired.")


def check_capability_engine_ready(capability_engine: Any) -> CheckResult:
    if capability_engine is None:
        return CheckResult(
            check_id="capability_engine.ready",
            status=CheckStatus.FAILED,
            message="Capability engine missing.",
            remediation="Initialize capability engine before startup.",
            severity=Severity.CRITICAL,
        )
    cfg = getattr(capability_engine, "cfg", None)
    caps = getattr(cfg, "capabilities", None) if cfg is not None else None
    if not isinstance(caps, dict) or not caps:
        return CheckResult(
            check_id="capability_engine.config",
            status=CheckStatus.FAILED,
            message="Capability config missing or empty.",
            remediation="Load config/capabilities.json successfully before startup.",
            severity=Severity.CRITICAL,
        )
    intent_reqs = getattr(cfg, "intent_requirements", None) if cfg is not None else None
    if not isinstance(intent_reqs, dict) or not intent_reqs:
        return CheckResult(
            check_id="capability_engine.config",
            status=CheckStatus.FAILED,
            message="Capability intent requirements missing or empty.",
            remediation="Define intent_requirements in config/capabilities.json before startup.",
            severity=Severity.CRITICAL,
        )
    # Hard rule check: web cannot perform CAP_ADMIN_ACTION even if admin.
    try:
        from jarvis.core.capabilities.models import RequestContext, RequestSource

        test_intent = next(iter(intent_reqs.keys()))
        ctx = RequestContext(
            trace_id="startup",
            source=RequestSource.web,
            intent_id=str(test_intent),
            is_admin=True,
            extra_required_capabilities=["CAP_ADMIN_ACTION"],
        )
        dec = capability_engine.evaluate(ctx)
        if bool(getattr(dec, "allowed", False)) or "CAP_ADMIN_ACTION" not in list(getattr(dec, "denied_capabilities", []) or []):
            return CheckResult(
                check_id="capability_engine.hard_rules",
                status=CheckStatus.FAILED,
                message="Capability hard rules inactive.",
                remediation="Ensure capability engine enforces web/admin hard rules.",
                severity=Severity.CRITICAL,
            )
    except Exception as e:  # noqa: BLE001
        return CheckResult(
            check_id="capability_engine.hard_rules",
            status=CheckStatus.FAILED,
            message="Capability hard rule check failed.",
            remediation=str(e),
            severity=Severity.CRITICAL,
        )
    return CheckResult(check_id="capability_engine.ready", status=CheckStatus.OK, message="Capability engine ready.")


def check_policy_engine_presence(policy_engine: Any, *, policy_enabled: bool) -> CheckResult:
    if not bool(policy_enabled):
        return CheckResult(check_id="policy_engine", status=CheckStatus.OK, message="Policy disabled (skip engine check).")
    if policy_engine is None:
        return CheckResult(
            check_id="policy_engine",
            status=CheckStatus.FAILED,
            message="Policy enabled but engine missing.",
            remediation="Initialize policy engine or disable policy in config.",
            severity=Severity.CRITICAL,
        )
    return CheckResult(check_id="policy_engine", status=CheckStatus.OK, message="Policy engine ready.")


def check_dispatcher_policy_engine(dispatcher: Any, *, policy_enabled: bool) -> CheckResult:
    if not bool(policy_enabled):
        return CheckResult(check_id="dispatcher.policy_engine", status=CheckStatus.OK, message="Policy disabled (skip dispatcher wiring check).")
    if dispatcher is None:
        return CheckResult(
            check_id="dispatcher.policy_engine",
            status=CheckStatus.FAILED,
            message="Dispatcher missing.",
            remediation="Initialize dispatcher before startup checks.",
            severity=Severity.CRITICAL,
        )
    if getattr(dispatcher, "policy_engine", None) is None:
        return CheckResult(
            check_id="dispatcher.policy_engine",
            status=CheckStatus.FAILED,
            message="Dispatcher missing policy engine.",
            remediation="Wire policy engine into dispatcher.",
            severity=Severity.CRITICAL,
        )
    return CheckResult(check_id="dispatcher.policy_engine", status=CheckStatus.OK, message="Dispatcher policy engine wired.")


def check_policy_engine_config(policy_engine: Any, *, policy_enabled: bool) -> CheckResult:
    if not bool(policy_enabled):
        return CheckResult(check_id="policy_engine.config", status=CheckStatus.OK, message="Policy disabled (skip config check).")
    if policy_engine is None:
        return CheckResult(
            check_id="policy_engine.config",
            status=CheckStatus.FAILED,
            message="Policy engine missing.",
            remediation="Initialize policy engine before startup.",
            severity=Severity.CRITICAL,
        )
    try:
        status = policy_engine.status() if callable(getattr(policy_engine, "status", None)) else None
    except Exception as e:  # noqa: BLE001
        return CheckResult(
            check_id="policy_engine.config",
            status=CheckStatus.FAILED,
            message="Unable to verify policy engine status.",
            remediation=str(e),
            severity=Severity.CRITICAL,
        )
    if isinstance(status, dict):
        if bool(status.get("failsafe", False)):
            return CheckResult(
                check_id="policy_engine.config",
                status=CheckStatus.FAILED,
                message="Policy config failed validation (failsafe active).",
                remediation=str(status.get("error") or "Fix config/policy.json and restart."),
                severity=Severity.CRITICAL,
            )
        if not bool(status.get("enabled", False)):
            return CheckResult(
                check_id="policy_engine.config",
                status=CheckStatus.FAILED,
                message="Policy enabled in config but engine disabled.",
                remediation="Set policy.enabled=true in config/policy.json and restart.",
                severity=Severity.CRITICAL,
            )
        return CheckResult(check_id="policy_engine.config", status=CheckStatus.OK, message="Policy config validated.")
    # Fallback: inspect attributes when status() not available.
    cfg = getattr(policy_engine, "cfg", None)
    if cfg is None:
        return CheckResult(
            check_id="policy_engine.config",
            status=CheckStatus.FAILED,
            message="Policy config missing.",
            remediation="Load config/policy.json before startup.",
            severity=Severity.CRITICAL,
        )
    if bool(getattr(policy_engine, "_failsafe", False)):
        return CheckResult(
            check_id="policy_engine.config",
            status=CheckStatus.FAILED,
            message="Policy engine running in failsafe mode.",
            remediation="Fix config/policy.json and restart.",
            severity=Severity.CRITICAL,
        )
    if not bool(getattr(cfg, "enabled", False)):
        return CheckResult(
            check_id="policy_engine.config",
            status=CheckStatus.FAILED,
            message="Policy enabled in config but engine disabled.",
            remediation="Set policy.enabled=true in config/policy.json and restart.",
            severity=Severity.CRITICAL,
        )
    return CheckResult(check_id="policy_engine.config", status=CheckStatus.OK, message="Policy config validated.")


def check_privacy_store_presence(privacy_store: Any, *, privacy_enabled: bool) -> CheckResult:
    if not bool(privacy_enabled):
        return CheckResult(check_id="privacy_store", status=CheckStatus.OK, message="Privacy disabled (skip store check).")
    if privacy_store is None:
        return CheckResult(
            check_id="privacy_store",
            status=CheckStatus.FAILED,
            message="Privacy store missing.",
            remediation="Initialize privacy store before startup.",
            severity=Severity.CRITICAL,
        )
    return CheckResult(check_id="privacy_store", status=CheckStatus.OK, message="Privacy store ready.")


def check_privacy_gate_enforced(dispatcher: Any, privacy_store: Any, *, privacy_enabled: bool) -> CheckResult:
    if not bool(privacy_enabled):
        return CheckResult(check_id="privacy_gate", status=CheckStatus.OK, message="Privacy disabled (skip gate check).")
    if dispatcher is None:
        return CheckResult(
            check_id="privacy_gate",
            status=CheckStatus.FAILED,
            message="Dispatcher missing.",
            remediation="Initialize dispatcher before startup checks.",
            severity=Severity.CRITICAL,
        )
    gate = getattr(dispatcher, "_privacy_gate", None)
    if gate is None or not callable(getattr(gate, "evaluate", None)):
        return CheckResult(
            check_id="privacy_gate",
            status=CheckStatus.FAILED,
            message="Privacy gate missing.",
            remediation="Wire PrivacyGate into dispatcher.",
            severity=Severity.CRITICAL,
        )
    if privacy_store is not None and getattr(gate, "privacy_store", None) is not None and getattr(gate, "privacy_store", None) is not privacy_store:
        return CheckResult(
            check_id="privacy_gate",
            status=CheckStatus.FAILED,
            message="Privacy gate store mismatch.",
            remediation="Ensure dispatcher privacy gate uses the active privacy store.",
            severity=Severity.CRITICAL,
        )
    try:
        fn = getattr(dispatcher, "execute_loaded_module", None)
        code = getattr(fn, "__code__", None)
        names = set(code.co_names or []) | set(code.co_varnames or []) if code is not None else set()
        if code is None or "persistence_context" not in names:
            return CheckResult(
                check_id="privacy_gate",
                status=CheckStatus.FAILED,
                message="Dispatcher execution path missing privacy enforcement.",
                remediation="Wrap module execution in persistence_context via PrivacyGate.",
                severity=Severity.CRITICAL,
            )
    except Exception as e:  # noqa: BLE001
        return CheckResult(
            check_id="privacy_gate",
            status=CheckStatus.FAILED,
            message="Unable to verify privacy gate enforcement.",
            remediation=str(e),
            severity=Severity.CRITICAL,
        )
    return CheckResult(check_id="privacy_gate", status=CheckStatus.OK, message="Privacy gate enforced in dispatcher path.")


def check_web_remote_control(*, web_cfg: Dict[str, Any], secure_store: Any) -> CheckResult:
    if not bool((web_cfg or {}).get("enabled", False)):
        return CheckResult(check_id="web.remote_control", status=CheckStatus.OK, message="Web disabled (skip remote control checks).")
    if secure_store is None:
        return CheckResult(
            check_id="web.remote_control",
            status=CheckStatus.FAILED,
            message="Web enabled but secure store unavailable.",
            remediation="Initialize secure store before enabling web.",
            severity=Severity.CRITICAL,
        )
    try:
        st = secure_store.status()
        mode = st.mode.value if hasattr(st.mode, "value") else str(st.mode)
        if mode != "READY":
            return CheckResult(
                check_id="web.remote_control",
                status=CheckStatus.FAILED,
                message="Web enabled but secure store not READY.",
                remediation=str(getattr(st, "next_steps", "") or "Insert USB key to unlock secure store."),
                severity=Severity.CRITICAL,
            )
    except Exception as e:  # noqa: BLE001
        return CheckResult(
            check_id="web.remote_control",
            status=CheckStatus.FAILED,
            message="Secure store status check failed.",
            remediation=str(e),
            severity=Severity.CRITICAL,
        )
    try:
        if not bool(getattr(secure_store, "is_unlocked", lambda: False)()):
            return CheckResult(
                check_id="web.remote_control",
                status=CheckStatus.FAILED,
                message="Web enabled but secure store locked.",
                remediation="Unlock secure store before enabling web.",
                severity=Severity.CRITICAL,
            )
    except Exception as e:  # noqa: BLE001
        return CheckResult(
            check_id="web.remote_control",
            status=CheckStatus.FAILED,
            message="Unable to verify secure store unlocked.",
            remediation=str(e),
            severity=Severity.CRITICAL,
        )
    try:
        from jarvis.web.security.auth import ApiKeyStore

        keys = ApiKeyStore(secure_store).list_keys()
        if not keys:
            return CheckResult(
                check_id="web.api_keys",
                status=CheckStatus.FAILED,
                message="Web enabled but no API key configured.",
                remediation="Create an API key before enabling web (scripts/rotate_api_key.py).",
                severity=Severity.CRITICAL,
            )
    except Exception as e:  # noqa: BLE001
        return CheckResult(
            check_id="web.api_keys",
            status=CheckStatus.FAILED,
            message="Unable to verify API key presence.",
            remediation=str(e),
            severity=Severity.CRITICAL,
        )

    bind_host = str((web_cfg or {}).get("bind_host") or "127.0.0.1").strip() or "127.0.0.1"
    allow_remote = bool((web_cfg or {}).get("allow_remote", False))
    if not allow_remote and bind_host not in {"127.0.0.1", "localhost"}:
        return CheckResult(
            check_id="web.bind_host",
            status=CheckStatus.FAILED,
            message="Web bind_host must be localhost when allow_remote=false.",
            remediation="Set bind_host to 127.0.0.1 or enable allow_remote.",
            severity=Severity.CRITICAL,
        )
    return CheckResult(check_id="web.remote_control", status=CheckStatus.OK, message="Web remote control prerequisites OK.")


def check_module_discovery_no_import(modules_root: str) -> CheckResult:
    if not modules_root:
        return CheckResult(
            check_id="modules.discovery_no_import",
            status=CheckStatus.FAILED,
            message="Modules root not configured.",
            remediation="Configure modules root for discovery.",
            severity=Severity.CRITICAL,
        )
    try:
        from jarvis.core.modules.discovery import ModuleDiscovery

        called = {"n": 0}
        orig = importlib.import_module

        def boom(*_a, **_k):  # noqa: ANN001
            called["n"] += 1
            raise RuntimeError("import attempted during discovery")

        importlib.import_module = boom
        try:
            ModuleDiscovery(modules_root=str(modules_root)).scan()
        finally:
            importlib.import_module = orig
        if called["n"] > 0:
            return CheckResult(
                check_id="modules.discovery_no_import",
                status=CheckStatus.FAILED,
                message="Module discovery attempted imports.",
                remediation="Ensure module discovery reads only manifest/filesystem.",
                severity=Severity.CRITICAL,
            )
    except Exception as e:  # noqa: BLE001
        return CheckResult(
            check_id="modules.discovery_no_import",
            status=CheckStatus.FAILED,
            message="Module discovery no-import check failed.",
            remediation=str(e),
            severity=Severity.CRITICAL,
        )
    return CheckResult(check_id="modules.discovery_no_import", status=CheckStatus.OK, message="Module discovery no-import check passed.")

