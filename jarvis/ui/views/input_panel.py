from __future__ import annotations

from tkinter import ttk


class InputPanel(ttk.Frame):
    def __init__(self, master, *, on_send):  # noqa: ANN001
        super().__init__(master, padding=(8, 6))
        self._on_send = on_send

        self._entry = ttk.Entry(self)
        self._entry.grid(row=0, column=0, sticky="ew", padx=(0, 8))
        self._entry.bind("<Return>", lambda _e: self._handle_send())

        self._send_btn = ttk.Button(self, text="Send", command=self._handle_send)
        self._send_btn.grid(row=0, column=1)

        self._status = ttk.Label(self, text="")
        self._status.grid(row=1, column=0, columnspan=2, sticky="w", pady=(4, 0))

        self.columnconfigure(0, weight=1)

    def _handle_send(self) -> None:
        text = self._entry.get().strip()
        if not text:
            return
        self._entry.delete(0, "end")
        self._on_send(text)

    def set_enabled(self, enabled: bool, *, message: str = "") -> None:
        state = "normal" if enabled else "disabled"
        self._entry.configure(state=state)
        self._send_btn.configure(state=state)
        self._status.configure(text=message or "")

    def focus(self) -> None:
        try:
            self._entry.focus_set()
        except Exception:
            pass

