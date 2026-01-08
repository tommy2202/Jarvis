from __future__ import annotations

import time

from jarvis.core.security import AdminSession


def test_admin_session_expires_after_inactivity(monkeypatch):
    t = {"now": 1000.0}

    monkeypatch.setattr(time, "time", lambda: t["now"])
    s = AdminSession(timeout_seconds=10)
    s.unlock()
    assert s.is_admin() is True
    t["now"] += 11
    assert s.is_admin() is False

