from __future__ import annotations

import os
from dataclasses import dataclass

from jarvis.core.events import EventLogger
from jarvis.core.runtime import JarvisRuntime, RuntimeConfig
from jarvis.core.error_reporter import ErrorReporter
from jarvis.core.recovery import RecoveryPolicy, RecoveryConfig
from jarvis.core.circuit_breaker import BreakerRegistry


@dataclass
class JarvisRuntimeHarness:
    runtime: JarvisRuntime

    @classmethod
    def make(cls, *, tmp_path, jarvis_app, enable_tts: bool = False, tts=None):
        ev = EventLogger(str(tmp_path / "events.jsonl"))
        cfg = RuntimeConfig.model_validate(
            {
                "idle_sleep_seconds": 0.2,
                "timeouts": {"UNDERSTANDING": 2, "EXECUTING": 2, "SPEAKING": 2},
                "enable_voice": False,
                "enable_tts": bool(enable_tts),
                "enable_wake_word": False,
                "busy_policy": "queue",
                "result_ttl_seconds": 1,
            }
        )
        reporter = ErrorReporter(path=str(tmp_path / "errors.jsonl"))
        policy = RecoveryPolicy(RecoveryConfig())
        rt = JarvisRuntime(
            cfg=cfg,
            jarvis_app=jarvis_app,
            event_logger=ev,
            logger=type("L", (), {"warning": lambda *_a, **_k: None})(),
            error_reporter=reporter,
            recovery_policy=policy,
            breakers=BreakerRegistry({}),
            tts_adapter=tts,
            persist_path=str(tmp_path / "sm.jsonl"),
        )
        rt.start()
        return cls(runtime=rt)

