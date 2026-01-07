from __future__ import annotations

import queue
import threading
import time
from dataclasses import dataclass
from typing import Callable, Optional

from jarvis.core.events.models import BaseEvent


@dataclass
class _Worker:
    thread: threading.Thread
    q: "queue.Queue[BaseEvent]"
    stop: threading.Event


def start_worker(*, name: str, handler: Callable[[BaseEvent], None]) -> _Worker:
    q: "queue.Queue[BaseEvent]" = queue.Queue()
    stop = threading.Event()

    def run() -> None:
        while not stop.is_set():
            try:
                ev = q.get(timeout=0.1)
            except queue.Empty:
                continue
            try:
                handler(ev)
            except Exception:
                # handled at bus level; this is just a safety net
                pass

    t = threading.Thread(target=run, name=name, daemon=True)
    t.start()
    return _Worker(thread=t, q=q, stop=stop)


def stop_worker(w: _Worker, *, grace_seconds: float = 1.0) -> None:
    w.stop.set()
    w.thread.join(timeout=max(0.1, float(grace_seconds)))

