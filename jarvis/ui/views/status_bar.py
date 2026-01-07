from __future__ import annotations

from tkinter import ttk

from jarvis.ui.widgets.indicator import StatusIndicator


class StatusBar(ttk.Frame):
    def __init__(self, master, *, on_admin_clicked):  # noqa: ANN001
        super().__init__(master, padding=(8, 6))
        self._on_admin_clicked = on_admin_clicked

        self.state_ind = StatusIndicator(self, label="State")
        self.admin_ind = StatusIndicator(self, label="Admin")
        self.llm_ind = StatusIndicator(self, label="LLM (chat)")
        self.voice_ind = StatusIndicator(self, label="Voice")
        self.secure_ind = StatusIndicator(self, label="Secure store")

        self.state_ind.grid(row=0, column=0, padx=(0, 10), sticky="ew")
        self.admin_ind.grid(row=0, column=1, padx=(0, 10), sticky="ew")
        self.llm_ind.grid(row=0, column=2, padx=(0, 10), sticky="ew")
        self.voice_ind.grid(row=0, column=3, padx=(0, 10), sticky="ew")
        self.secure_ind.grid(row=0, column=4, padx=(0, 10), sticky="ew")

        self._admin_btn = ttk.Button(self, text="Unlock…", command=self._on_admin_clicked)
        self._admin_btn.grid(row=0, column=5, sticky="e")

        for c in range(6):
            self.columnconfigure(c, weight=1 if c < 5 else 0)

    def set_admin_button(self, *, is_admin: bool) -> None:
        self._admin_btn.configure(text=("Lock" if is_admin else "Unlock…"))

