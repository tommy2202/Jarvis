from __future__ import annotations

import json
from tkinter import ttk
from tkinter.scrolledtext import ScrolledText

from jarvis.ui.views.health_panel import HealthPanel


class LogsPanel(ttk.Frame):
    def __init__(self, master, *, on_refresh, on_export):  # noqa: ANN001
        super().__init__(master, padding=(8, 6))
        self._on_refresh = on_refresh
        self._on_export = on_export

        header = ttk.Frame(self)
        header.grid(row=0, column=0, sticky="ew")
        ttk.Label(header, text="Diagnostics").grid(row=0, column=0, sticky="w")
        self._severity = ttk.Combobox(header, values=["ALL", "INFO", "WARN", "ERROR", "CRITICAL", "HIGH"], width=10, state="readonly")
        self._severity.set("ALL")
        self._severity.grid(row=0, column=1, padx=(10, 6), sticky="w")
        ttk.Button(header, text="Refresh", command=self._on_refresh).grid(row=0, column=2, padx=(6, 0))
        ttk.Button(header, text="Export…", command=self._on_export).grid(row=0, column=3, padx=(6, 0))
        header.columnconfigure(0, weight=1)

        self._nb = ttk.Notebook(self)
        self._nb.grid(row=1, column=0, sticky="nsew", pady=(6, 0))

        self._errors = ScrolledText(self._nb, height=10, wrap="word")
        self._security = ScrolledText(self._nb, height=10, wrap="word")
        self._system = ScrolledText(self._nb, height=10, wrap="none")
        self._audit = ScrolledText(self._nb, height=10, wrap="word")
        self._health = HealthPanel(self._nb)
        self._caps = ScrolledText(self._nb, height=10, wrap="word")
        self._caps.configure(state="disabled")
        for t in (self._errors, self._security, self._system, self._audit):
            t.configure(state="disabled")

        self._nb.add(self._errors, text="Errors")
        self._nb.add(self._security, text="Security")
        self._nb.add(self._system, text="System")
        self._nb.add(self._audit, text="Audit")
        self._nb.add(self._health, text="Health")
        self._nb.add(self._caps, text="Capabilities")

        self.columnconfigure(0, weight=1)
        self.rowconfigure(1, weight=1)

    def severity_filter(self) -> str:
        return str(self._severity.get() or "ALL")

    def set_errors(self, items: list[dict]) -> None:
        self._set_jsonl(self._errors, items, severity_key="severity")

    def set_security(self, items: list[dict]) -> None:
        self._set_jsonl(self._security, items, severity_key="severity")

    def set_system_lines(self, lines: list[str]) -> None:
        self._system.configure(state="normal")
        self._system.delete("1.0", "end")
        self._system.insert("end", "\n".join(lines))
        self._system.configure(state="disabled")

    def set_audit_lines(self, lines: list[str]) -> None:
        self._audit.configure(state="normal")
        self._audit.delete("1.0", "end")
        self._audit.insert("end", "\n".join(lines))
        self._audit.configure(state="disabled")

    def set_health_snapshot(self, snap: dict) -> None:
        self._health.set_snapshot(snap)

    def set_capabilities_snapshot(self, payload: dict) -> None:
        self._caps.configure(state="normal")
        self._caps.delete("1.0", "end")
        try:
            self._caps.insert("end", json.dumps(payload, indent=2, ensure_ascii=False))
        except Exception:
            self._caps.insert("end", str(payload))
        self._caps.configure(state="disabled")

    def _set_jsonl(self, widget: ScrolledText, items: list[dict], *, severity_key: str) -> None:
        sev = self.severity_filter()
        widget.configure(state="normal")
        widget.delete("1.0", "end")
        for obj in items:
            if sev != "ALL":
                s = str(obj.get(severity_key) or "")
                if s != sev:
                    continue
            try:
                widget.insert("end", json.dumps(obj, ensure_ascii=False) + "\n")
            except Exception:
                continue
        widget.configure(state="disabled")

