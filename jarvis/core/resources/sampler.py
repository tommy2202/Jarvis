from __future__ import annotations

import os
import shutil
import time
from typing import Any, Dict, Optional

from jarvis.core.resources.models import ResourceSnapshot


class ResourceSampler:
    """
    Local-only sampler. Best effort:
    - CPU/RAM via psutil if installed
    - Disk free via shutil.disk_usage
    - GPU/VRAM via pynvml if installed and enabled
    """

    def __init__(self, *, root_path: str = ".", logs_path: str = "logs", enable_nvml: bool = True):
        self.root_path = root_path
        self.logs_path = logs_path
        self.enable_nvml = bool(enable_nvml)
        self._psutil = None
        self._proc = None
        try:
            import psutil  # type: ignore

            self._psutil = psutil
            self._proc = psutil.Process(os.getpid())
            # prime cpu_percent
            psutil.cpu_percent(interval=None)
            self._proc.cpu_percent(interval=None)
        except Exception:
            self._psutil = None
            self._proc = None

    def sample(self) -> ResourceSnapshot:
        out = ResourceSnapshot(sampled_at=time.time())
        psutil = self._psutil
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

        # Disk free (root + logs)
        out.disk_root_free_bytes = _disk_free_bytes(self.root_path)
        out.disk_logs_free_bytes = _disk_free_bytes(self.logs_path)

        # GPU VRAM (best effort)
        g = self._gpu_sample()
        out.gpu_status = str(g.get("status") or "unknown")
        out.gpu_vram_max_percent = g.get("vram_max_percent")
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
            count = int(pynvml.nvmlDeviceGetCount())
            max_pct: Optional[float] = None
            for i in range(count):
                h = pynvml.nvmlDeviceGetHandleByIndex(i)
                mem = pynvml.nvmlDeviceGetMemoryInfo(h)
                used = float(mem.used)
                total = float(mem.total) if mem.total else 0.0
                pct = (used / total * 100.0) if total else None
                if pct is None:
                    continue
                if max_pct is None or pct > max_pct:
                    max_pct = pct
            try:
                pynvml.nvmlShutdown()
            except Exception:
                pass
            return {"status": "ok", "vram_max_percent": max_pct}
        except Exception:
            try:
                pynvml.nvmlShutdown()
            except Exception:
                pass
            return {"status": "error"}


def _disk_free_bytes(path: str) -> Optional[int]:
    try:
        usage = shutil.disk_usage(path)
        return int(usage.free)
    except Exception:
        return None

