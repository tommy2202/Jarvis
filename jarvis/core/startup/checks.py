from __future__ import annotations

import hashlib
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

