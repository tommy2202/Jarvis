from __future__ import annotations

import time

from .helpers.fakes import FakeJarvisApp
from .helpers.harness import JarvisRuntimeHarness


def test_runtime_result_ttl_expires(tmp_path):
    h = JarvisRuntimeHarness.make(tmp_path=tmp_path, jarvis_app=FakeJarvisApp(), enable_tts=False)
    try:
        tid = h.runtime.submit_text("cli", "hi")
        assert h.runtime.wait_for_result(tid, timeout_seconds=2.0) is not None
        time.sleep(1.2)
        assert h.runtime.get_result(tid) is None
    finally:
        h.runtime.stop()

