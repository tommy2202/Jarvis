from __future__ import annotations

import os
import shutil
import time
from dataclasses import dataclass
from typing import Any, Dict, Optional

from jarvis.core.telemetry.models import ResourceSample
from jarvis.core.telemetry.redaction import telemetry_redact


@dataclass(frozen=True)
class ResourceThresholds:
    cpu_warn_percent: float = 85.0
    ram_warn_percent: float = 85.0
    disk_warn_percent_used: float = 90.0
    gpu_vram_warn_percent: float = 90.0


class ResourceSampler:
    def __init__(self, *, root_path: str = ".", logs_path: str = "logs", enable_nvml: bool = True):
        self.root_path = root_path
        self.logs_path = logs_path
        self.enable_nvml = bool(enable_nvml)
        self._psutil = None
        try:
            import psutil  # type: ignore

            self._psutil = psutil
        except Exception:
            self._psutil = None

        self._proc = None
        if self._psutil is not None:
            try:
                self._proc = self._psutil.Process(os.getpid())
                # prime cpu_percent
                self._psutil.cpu_percent(interval=None)
                self._proc.cpu_percent(interval=None)
            except Exception:
                self._proc = None

    def has_psutil(self) -> bool:
        return self._psutil is not None

    def sample(self) -> ResourceSample:
        psutil = self._psutil
        out = ResourceSample(sampled_at=time.time())

        # CPU/RAM (best effort)
        if psutil is not None:
            try:
                out.cpu_system_percent = float(psutil.cpu_percent(interval=None))
            except Exception:
                out.cpu_system_percent = None
            try:
                vm = psutil.virtual_memory()
                out.ram_system_percent = float(vm.percent)
            except Exception:
                out.ram_system_percent = None
            if self._proc is not None:
                try:
                    out.cpu_process_percent = float(self._proc.cpu_percent(interval=None))
                except Exception:
                    out.cpu_process_percent = None
                try:
                    mi = self._proc.memory_info()
                    out.ram_process_rss_bytes = int(mi.rss)
                except Exception:
                    out.ram_process_rss_bytes = None

        # Disk (root + logs)
        out.disk_root_percent_used = _disk_percent_used(self.root_path)
        out.disk_logs_percent_used = _disk_percent_used(self.logs_path)

        # GPU (best effort, optional)
        out.gpu = telemetry_redact(self._gpu_sample())  # safe small dict
        return out

    def _gpu_sample(self) -> Dict[str, Any]:
        if not self.enable_nvml:
            return {"status": "disabled"}
        try:
            import pynvml  # type: ignore
        except Exception:
            return {"status": "unavailable"}

        try:
            pynvml.nvmlInit()
            count = pynvml.nvmlDeviceGetCount()
            gpus = []
            for i in range(int(count)):
                h = pynvml.nvmlDeviceGetHandleByIndex(i)
                name = pynvml.nvmlDeviceGetName(h)
                mem = pynvml.nvmlDeviceGetMemoryInfo(h)
                used = float(mem.used)
                total = float(mem.total) if mem.total else 0.0
                pct = (used / total * 100.0) if total else None
                gpus.append({"index": i, "name": name.decode("utf-8", errors="ignore") if isinstance(name, (bytes, bytearray)) else str(name), "vram_used_bytes": int(used), "vram_total_bytes": int(total), "vram_percent": pct})
            try:
                pynvml.nvmlShutdown()
            except Exception:
                pass
            return {"status": "ok", "gpus": gpus}
        except Exception:
            try:
                pynvml.nvmlShutdown()
            except Exception:
                pass
            return {"status": "error"}


def _disk_percent_used(path: str) -> Optional[float]:
    try:
        usage = shutil.disk_usage(path)
        used = float(usage.used)
        total = float(usage.total)
        if total <= 0:
            return None
        return float((used / total) * 100.0)
    except Exception:
        return None

