from __future__ import annotations

import json
import threading
import time
import tkinter as tk
from tkinter import messagebox, ttk

from jarvis.core.errors import JarvisError
from jarvis.ui.ui_events import UiController
from jarvis.ui.ui_models import CoreClient, UiConfig
from jarvis.ui.views.conversation import ConversationPanel
from jarvis.ui.views.input_panel import InputPanel
from jarvis.ui.views.jobs_panel import JobsPanel
from jarvis.ui.views.logs_panel import LogsPanel
from jarvis.ui.views.status_bar import StatusBar
from jarvis.ui.views.voice_controls import VoiceControls
from jarvis.ui.widgets.modal_dialogs import PassphraseDialog


class MainWindow(ttk.Frame):
    def __init__(self, master: tk.Tk, *, core: CoreClient, config: UiConfig, logger):  # noqa: ANN001
        super().__init__(master)
        self.master = master
        self.core = core
        self.cfg = config
        self.logger = logger
        self.controller = UiController(core)

        self._pending: dict[str, dict] = {}
        self._last_status: dict | None = None
        self._core_ok = True
        self._refresh_interval = max(250, int(self.cfg.refresh_interval_ms))

        self._build()
        self._schedule_poll()

    def _build(self) -> None:
        self.master.title("Jarvis Desktop")
        self.grid(row=0, column=0, sticky="nsew")
        self.master.rowconfigure(0, weight=1)
        self.master.columnconfigure(0, weight=1)

        self._banner = ttk.Label(self, text="", foreground="#c62828")
        self._banner.grid(row=0, column=0, sticky="ew", padx=8, pady=(6, 0))

        self.status = StatusBar(self, on_admin_clicked=self._on_admin_clicked)
        self.status.grid(row=1, column=0, sticky="ew", padx=8, pady=(6, 0))

        self.convo = ConversationPanel(self)
        self.convo.grid(row=2, column=0, sticky="nsew", padx=8, pady=(6, 0))

        self.input = InputPanel(self, on_send=self._on_send_text)
        self.input.grid(row=3, column=0, sticky="ew", padx=8, pady=(6, 0))

        self.voice = VoiceControls(self, on_voice_toggle=self._on_voice_toggle, on_wake_toggle=self._on_wake_toggle, on_push_to_talk=self._on_push_to_talk)
        self.voice.grid(row=4, column=0, sticky="ew", padx=8, pady=(6, 0))

        bottom = ttk.Panedwindow(self, orient="horizontal")
        bottom.grid(row=5, column=0, sticky="nsew", padx=8, pady=(6, 8))

        self.jobs = JobsPanel(bottom, on_cancel=self._on_cancel_job, on_view=self._on_view_job)
        self.logs = LogsPanel(bottom, on_refresh=self._refresh_logs, on_export=self._export_logs)
        bottom.add(self.jobs, weight=1)
        bottom.add(self.logs, weight=2)

        self.columnconfigure(0, weight=1)
        self.rowconfigure(2, weight=2)
        self.rowconfigure(5, weight=1)

        self.input.focus()

    def _ui_error(self, exc: BaseException) -> None:
        try:
            self.logger.exception("UI callback error: %s", exc)
        except Exception:
            pass
        messagebox.showerror("UI error", "UI error — see logs.")

    def _set_banner(self, text: str) -> None:
        self._banner.configure(text=text or "")

    def _on_send_text(self, text: str) -> None:
        try:
            self.convo.append(role="user", message=text)
            trace_id = self.controller.send_text(text=text, client_meta={"client": "desktop"})
            self._pending[trace_id] = {"text": text, "sent_at": time.time()}
            self.convo.append(role="system", message=f"Sent (trace_id={trace_id[:8]}…).")
        except Exception as e:  # noqa: BLE001
            self._ui_error(e)

    def _on_admin_clicked(self) -> None:
        try:
            st = self.core.get_status()
            is_admin = bool((st.get("admin") or {}).get("is_admin", False))
            if is_admin:
                self.core.admin_lock()
                self.convo.append(role="system", message="Admin locked.")
                return
            dlg = PassphraseDialog(self.master)
            self.master.wait_window(dlg)
            pw = dlg.result()
            if pw is None:
                return
            # unlock in background (scrypt can be slow)
            def run():
                ok = False
                try:
                    ok = bool(self.core.admin_unlock(pw))
                except Exception:
                    ok = False

                def done():
                    self.convo.append(role="system", message=("Admin unlocked." if ok else "Admin unlock failed."))

                self.master.after(0, done)

            threading.Thread(target=run, name="ui-admin-unlock", daemon=True).start()
        except Exception as e:  # noqa: BLE001
            self._ui_error(e)

    def _on_voice_toggle(self, enabled: bool) -> None:
        try:
            self.core.set_voice_enabled(enabled)
        except Exception as e:  # noqa: BLE001
            self._ui_error(e)

    def _on_wake_toggle(self, enabled: bool) -> None:
        try:
            self.core.set_wake_word_enabled(enabled)
        except Exception as e:  # noqa: BLE001
            self._ui_error(e)

    def _on_push_to_talk(self) -> None:
        try:
            trace_id = self.core.request_listen(source="ui")
            self.convo.append(role="system", message=f"Listening… (trace_id={trace_id[:8]}…)")
        except Exception as e:  # noqa: BLE001
            self._ui_error(e)

    def _on_cancel_job(self, job_id: str) -> None:
        try:
            ok = self.core.cancel_job(job_id)
            self.convo.append(role="system", message=("Job canceled." if ok else "Unable to cancel job."))
        except JarvisError as e:
            self.convo.append(role="system", message=e.user_message)
        except Exception as e:  # noqa: BLE001
            self._ui_error(e)

    def _on_view_job(self, job_id: str) -> None:
        try:
            # UI is thin: show the summary only (full job details are available via CLI/web).
            jobs = self.core.get_jobs_summary(limit=200)
            for j in jobs:
                if str(j.get("id")) == job_id:
                    messagebox.showinfo("Job details", json.dumps(j, indent=2, ensure_ascii=False))
                    return
            messagebox.showinfo("Job details", "Job not found (may have been cleaned up).")
        except Exception as e:  # noqa: BLE001
            self._ui_error(e)

    def _refresh_logs(self) -> None:
        try:
            n = int(getattr(self.cfg, "max_log_entries_displayed", 200))
            self.logs.set_errors(self.core.get_recent_errors(n=n))
            self.logs.set_security(self.core.get_recent_security_events(n=n))
            self.logs.set_system_lines(self.core.get_recent_system_logs(n=n))
            audit_lines = getattr(self.core, "get_audit_tail", lambda n=30: [])(n=min(200, n))
            if audit_lines:
                self.logs.set_audit_lines(audit_lines)
            snap = getattr(self.core, "get_telemetry_snapshot", lambda: None)()
            if snap:
                self.logs.set_health_snapshot(snap)
            caps = getattr(self.core, "get_capabilities_snapshot", lambda: None)()
            if caps:
                self.logs.set_capabilities_snapshot(caps)
        except Exception as e:  # noqa: BLE001
            self._ui_error(e)

    def _export_logs(self) -> None:
        try:
            st = self.core.get_status()
            is_admin = bool((st.get("admin") or {}).get("is_admin", False))
            if not is_admin:
                messagebox.showwarning("Admin required", "Admin required to export logs.")
                return
            from tkinter.filedialog import asksaveasfilename

            path = asksaveasfilename(title="Export logs", defaultextension=".json", filetypes=[("JSON", "*.json")])
            if not path:
                return
            payload = {
                "status": st,
                "errors": self.core.get_recent_errors(n=int(getattr(self.cfg, "max_log_entries_displayed", 200))),
                "security": self.core.get_recent_security_events(n=int(getattr(self.cfg, "max_log_entries_displayed", 200))),
                "system": self.core.get_recent_system_logs(n=int(getattr(self.cfg, "max_log_entries_displayed", 200))),
            }
            with open(path, "w", encoding="utf-8") as f:
                json.dump(payload, f, indent=2, ensure_ascii=False)
            messagebox.showinfo("Export", "Exported.")
        except Exception as e:  # noqa: BLE001
            self._ui_error(e)

    def _schedule_poll(self) -> None:
        self.master.after(self._refresh_interval, self._poll)

    def _poll(self) -> None:
        try:
            st = self.core.get_status()
            self._core_ok = True
            self._set_banner("")
            self._apply_status(st)
            self._poll_pending()
            try:
                getattr(self.core, "ui_heartbeat")()
            except Exception:
                pass
        except Exception:
            self._core_ok = False
            self._set_banner("Jarvis core unavailable")
            self.input.set_enabled(False, message="Core unavailable.")
        finally:
            self._schedule_poll()

    def _apply_status(self, st: dict) -> None:
        state = str(st.get("state") or "—")
        admin = st.get("admin") or {}
        secure = st.get("secure_store") or {}
        llm = st.get("llm") or {}
        voice = st.get("voice") or {}

        # State indicator
        level = "ok" if state in {"SLEEPING", "IDLE"} else "warn"
        if state in {"ERROR_RECOVERY"}:
            level = "error"
        self.status.state_ind.set(value=state, level=level)

        # Admin indicator + button
        is_admin = bool(admin.get("is_admin", False))
        rem = int(admin.get("remaining_seconds", 0) or 0)
        self.status.admin_ind.set(value=("UNLOCKED" if is_admin else "LOCKED") + (f" ({rem}s)" if is_admin else ""), level=("ok" if is_admin else "warn"))
        self.status.set_admin_button(is_admin=is_admin)

        # Secure store
        mode = str(secure.get("mode") or "—")
        sec_level = "ok" if mode in {"READY", "READ_ONLY"} else "warn"
        if mode in {"STORE_CORRUPT", "KEY_MISMATCH"}:
            sec_level = "error"
        self.status.secure_ind.set(value=mode, level=sec_level)
        if mode in {"KEY_MISSING"}:
            self._set_banner("USB key missing — secure features disabled.")

        # LLM (chat)
        chat = (llm.get("roles") or {}).get("chat") if isinstance(llm, dict) else None
        if isinstance(chat, dict):
            loaded = bool(chat.get("loaded", False))
            val = "loaded" if loaded else "idle"
            lvl = "ok" if loaded else "neutral"
        else:
            val = "unavailable"
            lvl = "warn"
        self.status.llm_ind.set(value=val, level=lvl)

        # Voice
        v_available = bool(voice.get("available", False))
        v_enabled = bool(voice.get("voice_enabled", False))
        w_enabled = bool(voice.get("wake_word_enabled", False))
        v_val = ("on" if v_enabled else "off") + ("/wake" if w_enabled else "")
        self.status.voice_ind.set(value=v_val, level=("ok" if (v_available and v_enabled) else "warn" if v_available else "neutral"))
        self.voice.set_state(available=v_available, voice_enabled=v_enabled, wake_enabled=w_enabled)

        # Input enabling (avoid blocking core; just a UX constraint)
        runtime_cfg = st.get("runtime_cfg") or {}
        max_conc = int(runtime_cfg.get("max_concurrent_interactions", 1) or 1)
        busy = state not in {"SLEEPING", "IDLE"}
        shutting_down = bool((st.get("shutdown") or {}).get("in_progress", False))
        if max_conc <= 1 and busy:
            self.input.set_enabled(False, message="Jarvis is busy…")
        elif shutting_down:
            self.input.set_enabled(False, message="Shutting down…")
        else:
            self.input.set_enabled(True, message="")

        # Jobs + logs
        try:
            self.jobs.set_jobs(self.core.get_jobs_summary(limit=50))
            self.jobs.set_admin_enabled(is_admin=is_admin)
        except Exception:
            pass

        # Refresh logs only when tab changes or periodically? Keep simple: refresh every poll with cap.
        if self._last_status is None or (time.time() % 2.0) < (self._refresh_interval / 1000.0):
            try:
                self._refresh_logs()
            except Exception:
                pass

        self._last_status = st

    def _poll_pending(self) -> None:
        for trace_id in list(self._pending.keys()):
            res = self.core.get_result(trace_id)
            if not res:
                continue
            reply = str(res.get("reply") or "")
            self.convo.append(role="jarvis", message=reply)
            self._pending.pop(trace_id, None)

