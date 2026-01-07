from __future__ import annotations

import tkinter as tk
from tkinter import ttk


class StatusIndicator(ttk.Frame):
    """
    A small indicator: colored dot + text.
    Color is supplemental; text carries meaning.
    """

    def __init__(self, master, *, label: str, width: int = 10):  # noqa: ANN001
        super().__init__(master)
        self._label_text = ttk.Label(self, text=label)
        self._label_text.grid(row=0, column=0, padx=(0, 6), sticky="w")

        self._canvas = tk.Canvas(self, width=width, height=width, highlightthickness=0)
        self._dot = self._canvas.create_oval(1, 1, width - 1, width - 1, fill="#999999", outline="#666666")
        self._canvas.grid(row=0, column=1, padx=(0, 6), sticky="w")

        self._value = ttk.Label(self, text="—")
        self._value.grid(row=0, column=2, sticky="w")

        self.columnconfigure(2, weight=1)

    def set(self, *, value: str, level: str) -> None:
        """
        level: ok|warn|error|neutral
        """
        color = {
            "ok": "#2e7d32",
            "warn": "#f9a825",
            "error": "#c62828",
            "neutral": "#999999",
        }.get(level, "#999999")
        self._canvas.itemconfigure(self._dot, fill=color)
        self._value.configure(text=value)

