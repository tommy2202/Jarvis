from __future__ import annotations

import os
import threading
import time
from dataclasses import dataclass
from typing import Callable, Dict, Optional


@dataclass
class WatcherConfig:
    enabled: bool = False
    debounce_ms: int = 500
    poll_interval_ms: int = 500


class ConfigWatcher:
    """
    Safe, debounced watcher for non-sensitive config files.
    Uses watchdog if installed; otherwise falls back to polling.
    """

    def __init__(self, *, config_dir: str, cfg: WatcherConfig, on_change: Callable[[], None], logger):
        self.config_dir = config_dir
        self.cfg = cfg
        self.on_change = on_change
        self.logger = logger
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._poll_loop, name="config-watcher", daemon=True)
        self._last_mtimes: Dict[str, float] = {}
        self._last_fire = 0.0

    def start(self) -> None:
        if not self.cfg.enabled:
            return
        if self._thread.is_alive():
            return
        self._stop.clear()
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread.is_alive():
            self._thread.join(timeout=2.0)

    def _poll_loop(self) -> None:
        interval = max(0.1, float(self.cfg.poll_interval_ms) / 1000.0)
        debounce = max(0.1, float(self.cfg.debounce_ms) / 1000.0)
        while not self._stop.is_set():
            try:
                changed = False
                for name in os.listdir(self.config_dir):
                    if not name.endswith(".json"):
                        continue
                    path = os.path.join(self.config_dir, name)
                    if not os.path.isfile(path):
                        continue
                    m = os.path.getmtime(path)
                    prev = self._last_mtimes.get(path)
                    if prev is None:
                        self._last_mtimes[path] = m
                        continue
                    if m != prev:
                        self._last_mtimes[path] = m
                        changed = True

                now = time.time()
                if changed and (now - self._last_fire) >= debounce:
                    self._last_fire = now
                    self.on_change()
            except Exception as e:  # noqa: BLE001
                self.logger.warning(f"Config watcher error: {e}")
            time.sleep(interval)

