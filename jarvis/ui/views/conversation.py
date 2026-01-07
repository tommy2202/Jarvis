from __future__ import annotations

import tkinter as tk
from tkinter import ttk
from tkinter.scrolledtext import ScrolledText


class ConversationPanel(ttk.Frame):
    def __init__(self, master):  # noqa: ANN001
        super().__init__(master, padding=(8, 6))
        self._text = ScrolledText(self, height=18, wrap=tk.WORD)
        self._text.grid(row=0, column=0, sticky="nsew")
        self._text.configure(state="disabled")

        # tags (visual differentiation)
        self._text.tag_configure("user", foreground="#1565c0")
        self._text.tag_configure("jarvis", foreground="#2e7d32")
        self._text.tag_configure("system", foreground="#6a1b9a")

        self.columnconfigure(0, weight=1)
        self.rowconfigure(0, weight=1)

    def append(self, *, role: str, message: str) -> None:
        tag = role if role in {"user", "jarvis", "system"} else "system"
        prefix = {"user": "You", "jarvis": "Jarvis", "system": "System"}.get(tag, "System")
        line = f"{prefix}: {message}\n"
        self._text.configure(state="normal")
        self._text.insert("end", line, (tag,))
        self._text.configure(state="disabled")
        self._text.see("end")

