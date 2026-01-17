from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass
from typing import Any, Dict, Optional, Tuple

from jarvis.core.ops_log import OpsLogger
from jarvis.core.startup.checks import hash_runtime_fingerprint
from jarvis.core.startup.decision import decide
from jarvis.core.startup.models import OverallStatus, StartupCheckResult
from jarvis.core.startup.phases import (
    phase0_bootstrap_integrity,
    phase1_config_validation,
    phase2_secure_store,
    phase3_runtime_state,
    phase4_core_readiness,
    phase5_optional_probing,
    phase6_policy_safety,
    phase7_enforcement_chain,
)
from jarvis.core.events.models import BaseEvent, EventSeverity, SourceSubsystem
from jarvis.core.startup.models import CheckStatus


@dataclass
class StartupFlags:
    force_start: bool = False
    safe_mode: bool = False
    diagnostics_only: bool = False


class StartupSelfCheckRunner:
    def __init__(self, *, ops: OpsLogger, logger=None, event_bus=None, telemetry=None):
        self.ops = ops
        self.logger = logger
        self.event_bus = event_bus
        self.telemetry = telemetry

    def run(
        self,
        *,
        flags: StartupFlags,
        root_dir: str,
        logs_dir: str,
        config_manager,
        secure_store,
        runtime_state,
        cfg_obj,
        capabilities_cfg_raw: Dict[str, Any],
        core_ready: Dict[str, bool],
        dispatcher=None,
        capability_engine=None,
        policy_engine=None,
        privacy_store=None,
        modules_root: str = "",
    ) -> StartupCheckResult:
        self.ops.log(trace_id="startup", event="startup.self_check.begin", outcome="start", details={"force_start": flags.force_start, "safe_mode": flags.safe_mode})
        if self.telemetry is not None:
            try:
                self.telemetry.increment_counter("startup_self_check_total", 1)
            except Exception:
                pass

        phases = []
        ph0 = phase0_bootstrap_integrity(root_dir=root_dir, logs_dir=logs_dir)
        phases.append(ph0)
        ph1, cfg_fp = phase1_config_validation(config_manager=config_manager)
        phases.append(ph1)
        ph2 = phase2_secure_store(secure_store=secure_store)
        phases.append(ph2)
        ph3 = phase3_runtime_state(runtime_state=runtime_state)
        phases.append(ph3)
        ph4 = phase4_core_readiness(**core_ready)
        phases.append(ph4)
        ph5 = phase5_optional_probing(cfg_obj=cfg_obj)
        phases.append(ph5)

        secure_mode = "UNKNOWN"
        try:
            secure_mode = secure_store.status().mode.value
        except Exception:
            secure_mode = "UNKNOWN"
        ph6 = phase6_policy_safety(cfg_obj=cfg_obj, secure_store_mode=secure_mode, capabilities_cfg=capabilities_cfg_raw)
        phases.append(ph6)

        ph7 = phase7_enforcement_chain(
            dispatcher=dispatcher,
            capability_engine=capability_engine,
            policy_engine=policy_engine,
            privacy_store=privacy_store,
            secure_store=secure_store,
            cfg_obj=cfg_obj,
            modules_root=modules_root,
        )
        phases.append(ph7)

        d = decide(phases=phases, force_start=flags.force_start, safe_mode_flag=flags.safe_mode)

        blocking = []
        warnings = []
        remediation = []
        for ph in phases:
            for ck in ph.checks:
                if ck.status == "FAILED":
                    blocking.append(f"{ph.name}:{ck.check_id}: {ck.message}")
                    if ck.remediation:
                        remediation.append(ck.remediation)
                if ck.status == "DEGRADED":
                    warnings.append(f"{ph.name}:{ck.check_id}: {ck.message}")
                    if ck.remediation:
                        remediation.append(ck.remediation)

        fp = hash_runtime_fingerprint(
            f"cfg_version={getattr(cfg_obj.app, 'config_version', 0)}",
            f"cfg_files={json.dumps(cfg_fp, sort_keys=True)}",
            f"caps_hash={hash_runtime_fingerprint(json.dumps(capabilities_cfg_raw, sort_keys=True))}",
        )

        result = StartupCheckResult(
            overall_status=d.status,
            started_in_safe_mode=bool(d.safe_mode),
            phases=phases,
            blocking_reasons=blocking if d.status == OverallStatus.BLOCKED else [],
            warnings=warnings,
            remediation_steps=remediation,
            runtime_fingerprint=fp,
        )

        # persist report
        try:
            os.makedirs("logs", exist_ok=True)
            with open(os.path.join("logs", "startup_report.json"), "w", encoding="utf-8") as f:
                json.dump(result.model_dump(), f, indent=2, ensure_ascii=False)
        except Exception:
            pass

        self.ops.log(trace_id="startup", event="startup.self_check.complete", outcome=result.overall_status.value, details={"safe_mode": result.started_in_safe_mode})
        any_failed = any(c.status == CheckStatus.FAILED for ph in phases for c in (ph.checks or []))
        if any_failed:
            if self.logger is not None:
                try:
                    self.logger.critical("Startup checks failed (fail-closed).")
                except Exception:
                    pass
            if self.event_bus is not None:
                try:
                    self.event_bus.publish_nowait(
                        BaseEvent(
                            event_type="startup.failed",
                            trace_id="startup",
                            source_subsystem=SourceSubsystem.telemetry,
                            severity=EventSeverity.CRITICAL,
                            payload={"blocking_reasons": list(blocking)[:50]},
                        )
                    )
                except Exception:
                    pass
        if self.telemetry is not None:
            try:
                self.telemetry.set_gauge("startup_safe_mode", 1 if result.started_in_safe_mode else 0)
            except Exception:
                pass
        return result

