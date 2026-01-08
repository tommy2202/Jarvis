from __future__ import annotations

import json
from typing import Any, Dict

from jarvis.core.startup.models import StartupCheckResult


def to_human(result: StartupCheckResult) -> str:
    lines = []
    lines.append(f"Startup self-check: {result.overall_status.value} (safe_mode={result.started_in_safe_mode})")
    for ph in result.phases:
        lines.append(f"- Phase {ph.phase_id}: {ph.name}: {ph.status.value}")
        for ck in ph.checks:
            lines.append(f"  - {ck.check_id}: {ck.status.value} - {ck.message}")
            if ck.remediation:
                lines.append(f"    remediation: {ck.remediation}")
    if result.blocking_reasons:
        lines.append("Blocking reasons:")
        for r in result.blocking_reasons:
            lines.append(f"- {r}")
    if result.warnings:
        lines.append("Warnings:")
        for w in result.warnings:
            lines.append(f"- {w}")
    if result.remediation_steps:
        lines.append("Next steps:")
        for s in result.remediation_steps:
            lines.append(f"- {s}")
    return "\n".join(lines)


def to_json_dict(result: StartupCheckResult) -> Dict[str, Any]:
    return result.model_dump()

