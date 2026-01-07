from __future__ import annotations

import tkinter as tk
from tkinter import ttk


class PassphraseDialog(tk.Toplevel):
    def __init__(self, master, *, title: str = "Admin unlock"):  # noqa: ANN001
        super().__init__(master)
        self.title(title)
        self.resizable(False, False)
        self.transient(master)
        self.grab_set()

        self._result: str | None = None

        frm = ttk.Frame(self, padding=12)
        frm.grid(row=0, column=0, sticky="nsew")

        ttk.Label(frm, text="Passphrase:").grid(row=0, column=0, sticky="w")
        self._entry = ttk.Entry(frm, show="•", width=32)
        self._entry.grid(row=1, column=0, sticky="ew", pady=(4, 10))
        self._entry.focus_set()

        btns = ttk.Frame(frm)
        btns.grid(row=2, column=0, sticky="e")
        ok = ttk.Button(btns, text="Unlock", command=self._on_ok)
        cancel = ttk.Button(btns, text="Cancel", command=self._on_cancel)
        ok.grid(row=0, column=0, padx=(0, 8))
        cancel.grid(row=0, column=1)

        frm.columnconfigure(0, weight=1)

        self.bind("<Return>", lambda _e: self._on_ok())
        self.bind("<Escape>", lambda _e: self._on_cancel())

    def _on_ok(self) -> None:
        self._result = self._entry.get()
        self.destroy()

    def _on_cancel(self) -> None:
        self._result = None
        self.destroy()

    def result(self) -> str | None:
        return self._result

