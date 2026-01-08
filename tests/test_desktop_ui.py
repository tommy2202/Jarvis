from __future__ import annotations

import time

import pytest


class FakeCore:
    def __init__(self):
        self.calls = []
        self._results = {}
        self._status = {
            "state": "SLEEPING",
            "admin": {"available": True, "is_admin": False, "remaining_seconds": 0},
            "secure_store": {"mode": "KEY_MISSING"},
            "llm": {"enabled": False},
            "voice": {"available": False, "voice_enabled": False, "wake_word_enabled": False},
            "runtime_cfg": {"max_concurrent_interactions": 1, "busy_policy": "queue"},
        }

    def submit_text(self, source: str, text: str, client_meta=None):
        self.calls.append(("submit_text", source, text, client_meta))
        tid = f"t{len(self.calls)}"
        # respond later
        self._results[tid] = {"trace_id": tid, "reply": "ok", "intent": {"id": "system.test", "source": "stage_a", "confidence": 1.0}}
        return tid

    def get_result(self, trace_id: str):
        return self._results.get(trace_id)

    def get_status(self):
        self.calls.append(("get_status",))
        return self._status

    def admin_unlock(self, passphrase: str) -> bool:
        self.calls.append(("admin_unlock",))
        self._status["admin"]["is_admin"] = True
        self._status["admin"]["remaining_seconds"] = 100
        return True

    def admin_lock(self) -> None:
        self.calls.append(("admin_lock",))
        self._status["admin"]["is_admin"] = False
        self._status["admin"]["remaining_seconds"] = 0

    def request_sleep(self) -> None:
        self.calls.append(("request_sleep",))

    def request_shutdown(self) -> None:
        self.calls.append(("request_shutdown",))

    def wake(self) -> str:
        self.calls.append(("wake",))
        return "wake"

    def say(self, text: str, source: str = "system") -> str:
        self.calls.append(("say", text, source))
        return "say"

    def request_listen(self, source: str = "ui") -> str:
        self.calls.append(("request_listen", source))
        return "listen"

    def set_voice_enabled(self, enabled: bool) -> None:
        self.calls.append(("set_voice_enabled", enabled))
        self._status["voice"]["voice_enabled"] = bool(enabled)
        self._status["voice"]["available"] = True

    def set_wake_word_enabled(self, enabled: bool) -> None:
        self.calls.append(("set_wake_word_enabled", enabled))
        self._status["voice"]["wake_word_enabled"] = bool(enabled)

    def get_jobs_summary(self, limit: int = 50):
        self.calls.append(("get_jobs_summary", limit))
        return []

    def cancel_job(self, job_id: str) -> bool:
        self.calls.append(("cancel_job", job_id))
        return False

    def get_recent_errors(self, n: int = 50):
        self.calls.append(("get_recent_errors", n))
        return []

    def get_recent_security_events(self, n: int = 50):
        self.calls.append(("get_recent_security_events", n))
        return []

    def get_recent_system_logs(self, n: int = 200):
        self.calls.append(("get_recent_system_logs", n))
        return []


def test_ui_controller_send_calls_core():
    from jarvis.ui.ui_events import UiController

    core = FakeCore()
    c = UiController(core)
    tid = c.send_text(text="hello", client_meta={"x": 1})
    assert tid
    assert core.calls[0][0] == "submit_text"
    assert core.calls[0][1] == "ui"
    assert core.calls[0][2] == "hello"


def test_main_window_status_apply_smoke():
    # Headless-safe: if Tk cannot initialize (e.g. CI without display), skip.
    try:
        import tkinter as tk
        from tkinter import TclError
    except Exception:
        pytest.skip("tkinter not available")

    try:
        root = tk.Tk()
    except TclError:
        pytest.skip("Tk cannot initialize (headless)")

    try:
        from jarvis.ui.views.main_window import MainWindow
        from jarvis.ui.ui_models import UiConfig

        core = FakeCore()
        cfg = UiConfig(refresh_interval_ms=9999, max_log_entries_displayed=10, theme="light", confirm_on_exit=False)
        mw = MainWindow(root, core=core, config=cfg, logger=None)
        # Force status application
        mw._apply_status(core.get_status())
        # Admin-only cancel should be disabled when locked
        assert str(mw.jobs._cancel["state"]) == "disabled"
        # Flip admin on
        core._status["admin"]["is_admin"] = True
        mw._apply_status(core.get_status())
        assert str(mw.jobs._cancel["state"]) == "normal"
    finally:
        try:
            root.destroy()
        except Exception:
            pass

