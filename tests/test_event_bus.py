from __future__ import annotations

import time

import pytest


def test_publish_subscribe_multiple_subscribers(tmp_path):
    from jarvis.core.events.bus import EventBus, EventBusConfig
    from jarvis.core.events.models import BaseEvent, SourceSubsystem

    bus = EventBus(cfg=EventBusConfig(enabled=True, max_queue_size=100, worker_threads=2), logger=None)
    got1 = []
    got2 = []

    bus.subscribe("state.transition", lambda ev: got1.append(ev.event_id), priority=10)
    bus.subscribe("state.transition", lambda ev: got2.append(ev.event_id), priority=20)

    ev = BaseEvent(event_type="state.transition", source_subsystem=SourceSubsystem.state_machine, payload={"from": "A", "to": "B"})
    bus.publish(ev)
    time.sleep(0.2)
    assert got1 == [ev.event_id]
    assert got2 == [ev.event_id]
    bus.shutdown(0.5)


def test_handler_exception_isolated(tmp_path):
    from jarvis.core.events.bus import EventBus, EventBusConfig
    from jarvis.core.events.models import BaseEvent, SourceSubsystem

    bus = EventBus(cfg=EventBusConfig(enabled=True, max_queue_size=100, worker_threads=2), logger=None)
    ok = {"n": 0}

    def bad(_ev):  # noqa: ANN001
        raise RuntimeError("boom")

    def good(_ev):  # noqa: ANN001
        ok["n"] += 1

    bus.subscribe("state.transition", bad, priority=10)
    bus.subscribe("state.transition", good, priority=20)
    bus.publish(BaseEvent(event_type="state.transition", source_subsystem=SourceSubsystem.state_machine, payload={"x": 1}))
    time.sleep(0.2)
    assert ok["n"] == 1
    bus.shutdown(0.5)


def test_ordering_preserved_per_event_type(tmp_path):
    from jarvis.core.events.bus import EventBus, EventBusConfig
    from jarvis.core.events.models import BaseEvent, SourceSubsystem

    bus = EventBus(cfg=EventBusConfig(enabled=True, max_queue_size=100, worker_threads=2), logger=None)
    seen = []

    def handler(ev):  # noqa: ANN001
        if ev.event_type == "state.transition":
            seen.append(ev.payload["seq"])

    bus.subscribe("*", handler)
    for i in range(5):
        bus.publish(BaseEvent(event_type="state.transition", source_subsystem=SourceSubsystem.state_machine, payload={"seq": i}))
        bus.publish(BaseEvent(event_type="intent.routed", source_subsystem=SourceSubsystem.dispatcher, payload={"seq": i}))
    time.sleep(0.4)
    assert seen == [0, 1, 2, 3, 4]
    bus.shutdown(0.5)


def test_backpressure_drop_oldest(tmp_path):
    from jarvis.core.events.bus import EventBus, EventBusConfig, OverflowPolicy
    from jarvis.core.events.models import BaseEvent, SourceSubsystem

    # Start disabled so dispatcher doesn't drain; then enable enqueue.
    cfg = EventBusConfig(enabled=False, max_queue_size=10, overflow_policy=OverflowPolicy.DROP_OLDEST, worker_threads=1)
    bus = EventBus(cfg=cfg, logger=None)
    bus.set_enabled(True)
    for i in range(30):
        bus.publish(BaseEvent(event_type="state.transition", source_subsystem=SourceSubsystem.state_machine, payload={"i": i}))
    st = bus.get_stats()
    assert st["dropped_total"] >= 1
    bus.shutdown(0.1)


def test_shutdown_drains_queue(tmp_path):
    from jarvis.core.events.bus import EventBus, EventBusConfig
    from jarvis.core.events.models import BaseEvent, SourceSubsystem

    bus = EventBus(cfg=EventBusConfig(enabled=True, max_queue_size=100, worker_threads=1, shutdown_grace_seconds=1), logger=None)
    bus.subscribe("state.transition", lambda _ev: time.sleep(0.01))
    for i in range(20):
        bus.publish(BaseEvent(event_type="state.transition", source_subsystem=SourceSubsystem.state_machine, payload={"i": i}))
    bus.shutdown(1.0)
    assert bus.get_stats()["queue_depth"] == 0


def test_payload_validation_rejects_invalid_payload():
    from jarvis.core.events.models import BaseEvent, SourceSubsystem

    with pytest.raises(Exception):
        _ = BaseEvent(event_type="state.transition", source_subsystem=SourceSubsystem.state_machine, payload="nope")  # type: ignore[arg-type]

