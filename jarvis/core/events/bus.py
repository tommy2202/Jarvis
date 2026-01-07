from __future__ import annotations

import collections
import queue
import threading
import time
from dataclasses import dataclass
from enum import Enum
from typing import Any, Callable, Deque, Dict, List, Optional, Tuple

from pydantic import BaseModel, ConfigDict, Field

from jarvis.core.events.dispatcher import start_worker, stop_worker
from jarvis.core.events.models import BaseEvent, EventSeverity, SourceSubsystem
from jarvis.core.events.stats import StatsCounter


class OverflowPolicy(str, Enum):
    DROP_OLDEST = "DROP_OLDEST"
    DROP_NEWEST = "DROP_NEWEST"


class EventBusConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    enabled: bool = True
    max_queue_size: int = Field(default=1000, ge=10, le=100_000)
    worker_threads: int = Field(default=4, ge=1, le=64)
    overflow_policy: OverflowPolicy = OverflowPolicy.DROP_OLDEST
    shutdown_grace_seconds: float = Field(default=5.0, ge=0.1, le=60.0)
    log_dropped_events: bool = True
    keep_recent: int = 500


@dataclass
class _Sub:
    event_type: str
    handler: Callable[[BaseEvent], None]
    priority: int
    worker_name: str
    worker: Any


class EventBus:
    """
    In-process internal event bus.

    - publish is non-blocking (drop on overflow per policy)
    - ordering guarantee: each subscriber processes events sequentially
    - handler failures are isolated (caught) and emitted as error events
    """

    def __init__(self, *, cfg: EventBusConfig, logger=None, error_reporter=None, telemetry=None):
        self.cfg = cfg
        self.logger = logger
        self.error_reporter = error_reporter
        self.telemetry = telemetry

        self._lock = threading.Lock()
        self._cv = threading.Condition(self._lock)
        self._queue: Deque[BaseEvent] = collections.deque()
        self._subs: List[_Sub] = []
        self._running = False
        self._accepting = True
        self._stats = StatsCounter()
        self._dropped_tail: Deque[Dict[str, Any]] = collections.deque(maxlen=200)
        self._recent_events: Deque[Dict[str, Any]] = collections.deque(maxlen=max(100, int(cfg.keep_recent)))

        self._dispatcher_thread = threading.Thread(target=self._dispatch_loop, name="eventbus-dispatch", daemon=True)
        if self.cfg.enabled:
            self.start()

    def start(self) -> None:
        if self._running:
            return
        self._running = True
        self._accepting = True
        self._dispatcher_thread.start()

    def enabled(self) -> bool:
        return bool(self.cfg.enabled) and self._running

    def subscribe(self, event_type: str, handler: Callable[[BaseEvent], None], priority: int = 50) -> None:
        """
        event_type supports:
        - exact match ("state.transition")
        - prefix match ("state.*")
        - wildcard all ("*")
        """
        if not callable(handler):
            raise ValueError("handler must be callable")
        event_type = str(event_type)
        with self._lock:
            # one worker per handler to preserve ordering for that subscriber
            worker_name = f"eventbus-sub-{len(self._subs)+1}"
            worker = start_worker(name=worker_name, handler=lambda ev, h=handler: self._safe_handle(h, ev))
            self._subs.append(_Sub(event_type=event_type, handler=handler, priority=int(priority), worker_name=worker_name, worker=worker))
            self._subs.sort(key=lambda s: int(s.priority))
            self._stats.set_subscribers(len(self._subs))

    def unsubscribe(self, handler: Callable[[BaseEvent], None]) -> int:
        removed = 0
        with self._lock:
            keep: List[_Sub] = []
            for s in self._subs:
                if s.handler is handler:
                    removed += 1
                    try:
                        stop_worker(s.worker, grace_seconds=0.5)
                    except Exception:
                        pass
                else:
                    keep.append(s)
            self._subs = keep
            self._stats.set_subscribers(len(self._subs))
        return removed

    def publish(self, ev: BaseEvent) -> bool:
        return self._enqueue(ev, block=False)

    def publish_nowait(self, ev: BaseEvent) -> bool:
        return self._enqueue(ev, block=False)

    def get_stats(self) -> Dict[str, Any]:
        st = self._stats.snapshot()
        with self._lock:
            recent = list(self._recent_events)[:50]
        return {
            "enabled": self.enabled(),
            "published_total": st.published_total,
            "dropped_total": st.dropped_total,
            "delivered_total": st.delivered_total,
            "handler_errors_total": st.handler_errors_total,
            "queue_depth": st.queue_depth,
            "subscribers": st.subscribers,
            "per_type_published": st.per_type_published,
            "recent": recent,
        }

    def list_subscribers(self) -> List[Dict[str, Any]]:
        with self._lock:
            subs = list(self._subs)
        return [{"event_type": s.event_type, "priority": s.priority, "handler": getattr(s.handler, "__name__", "handler")} for s in subs]

    def dump_recent(self, n: int = 200) -> List[Dict[str, Any]]:
        with self._lock:
            return list(self._recent_events)[: max(1, int(n))]

    def set_enabled(self, enabled: bool) -> None:
        self.cfg.enabled = bool(enabled)

    def shutdown(self, grace_seconds: Optional[float] = None) -> None:
        self._accepting = False
        if grace_seconds is None:
            grace_seconds = float(self.cfg.shutdown_grace_seconds)
        deadline = time.time() + float(grace_seconds)
        # drain dispatcher queue
        with self._lock:
            self._cv.notify_all()
        while time.time() < deadline:
            with self._lock:
                if not self._queue:
                    break
            time.sleep(0.05)
        # stop dispatcher
        self._running = False
        with self._lock:
            self._cv.notify_all()
        try:
            if self._dispatcher_thread.is_alive():
                self._dispatcher_thread.join(timeout=max(0.1, float(grace_seconds)))
        except RuntimeError:
            # thread was never started (cfg.enabled=False at init)
            pass
        # stop workers
        with self._lock:
            subs = list(self._subs)
            self._subs = []
            self._stats.set_subscribers(0)
        for s in subs:
            try:
                stop_worker(s.worker, grace_seconds=0.5)
            except Exception:
                pass

    # ---- internals ----
    def _enqueue(self, ev: BaseEvent, *, block: bool) -> bool:
        if not self._accepting or not self.cfg.enabled:
            return False
        with self._lock:
            if len(self._queue) >= int(self.cfg.max_queue_size):
                if self.cfg.overflow_policy == OverflowPolicy.DROP_NEWEST:
                    self._stats.inc_dropped(1)
                    if self.cfg.log_dropped_events:
                        self._dropped_tail.appendleft({"event_type": ev.event_type, "trace_id": ev.trace_id, "reason": "drop_newest"})
                    return False
                # DROP_OLDEST
                dropped = self._queue.popleft()
                self._stats.inc_dropped(1)
                if self.cfg.log_dropped_events:
                    self._dropped_tail.appendleft({"event_type": dropped.event_type, "trace_id": dropped.trace_id, "reason": "drop_oldest"})
            self._queue.append(ev)
            self._stats.inc_published(ev.event_type)
            self._stats.set_queue_depth(len(self._queue))
            self._recent_events.appendleft(ev.model_dump())
            self._cv.notify()
            return True

    def _dispatch_loop(self) -> None:
        while self._running:
            with self._lock:
                if not self._queue:
                    self._stats.set_queue_depth(0)
                    self._cv.wait(timeout=0.2)
                    continue
                ev = self._queue.popleft()
                self._stats.set_queue_depth(len(self._queue))
                subs = list(self._subs)
            # deliver to matching subscribers (subscriber priority already sorted)
            delivered = 0
            for s in subs:
                if _match(s.event_type, ev.event_type):
                    try:
                        s.worker.q.put_nowait(ev)
                        delivered += 1
                    except Exception:
                        # should not happen; worker queue is unbounded
                        pass
            if delivered:
                self._stats.inc_delivered(delivered)
                if self.telemetry is not None:
                    try:
                        self.telemetry.increment_counter("events_delivered_total", delivered)
                    except Exception:
                        pass

    def _safe_handle(self, handler: Callable[[BaseEvent], None], ev: BaseEvent) -> None:
        t0 = time.time()
        try:
            handler(ev)
        except Exception as e:  # noqa: BLE001
            self._stats.inc_handler_error(1)
            # normalize/report without crashing the bus
            if self.error_reporter is not None:
                try:
                    self.error_reporter.report_exception(e, trace_id=ev.trace_id or "eventbus", subsystem="events", context={"event_type": ev.event_type})
                except Exception:
                    pass
            # emit an error event (best-effort, avoid recursion storms)
            try:
                err_ev = BaseEvent(
                    event_type="error.raised",
                    trace_id=ev.trace_id,
                    source_subsystem=SourceSubsystem.telemetry,
                    severity=EventSeverity.ERROR,
                    payload={"handler": getattr(handler, "__name__", "handler"), "event_type": ev.event_type, "error": str(e)[:500]},
                )
                self.publish_nowait(err_ev)
            except Exception:
                pass
        finally:
            if self.telemetry is not None:
                try:
                    self.telemetry.record_latency("event_handler_latency_ms", (time.time() - t0) * 1000.0, tags={"event_type": ev.event_type})
                except Exception:
                    pass


def _match(subscribed: str, event_type: str) -> bool:
    subscribed = str(subscribed)
    if subscribed == "*":
        return True
    if subscribed.endswith(".*"):
        return str(event_type).startswith(subscribed[:-2])
    return subscribed == event_type

