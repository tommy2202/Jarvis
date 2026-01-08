from __future__ import annotations

import json
from tkinter import ttk
from tkinter.scrolledtext import ScrolledText


class HealthPanel(ttk.Frame):
    def __init__(self, master):  # noqa: ANN001
        super().__init__(master, padding=(8, 6))

        top = ttk.Frame(self)
        top.grid(row=0, column=0, sticky="ew")
        ttk.Label(top, text="Subsystem health").grid(row=0, column=0, sticky="w")
        top.columnconfigure(0, weight=1)

        self._tree = ttk.Treeview(self, columns=("status", "message", "failures", "latency"), show="headings", height=8)
        self._tree.heading("status", text="Status")
        self._tree.heading("message", text="Message")
        self._tree.heading("failures", text="Failures")
        self._tree.heading("latency", text="Latency")
        self._tree.column("status", width=90, anchor="w")
        self._tree.column("message", width=420, anchor="w")
        self._tree.column("failures", width=70, anchor="e")
        self._tree.column("latency", width=80, anchor="e")
        self._tree.grid(row=1, column=0, sticky="nsew", pady=(6, 0))

        y = ttk.Scrollbar(self, orient="vertical", command=self._tree.yview)
        self._tree.configure(yscrollcommand=y.set)
        y.grid(row=1, column=1, sticky="ns", pady=(6, 0))

        bottom = ttk.Panedwindow(self, orient="horizontal")
        bottom.grid(row=2, column=0, columnspan=2, sticky="nsew", pady=(8, 0))

        self._resources = ScrolledText(bottom, height=8, wrap="word")
        self._events = ScrolledText(bottom, height=8, wrap="word")
        for t in (self._resources, self._events):
            t.configure(state="disabled")
        bottom.add(self._resources, weight=1)
        bottom.add(self._events, weight=2)

        self.columnconfigure(0, weight=1)
        self.rowconfigure(1, weight=1)
        self.rowconfigure(2, weight=1)

    def set_snapshot(self, snap: dict) -> None:
        health = snap.get("health") or []
        existing = set(self._tree.get_children(""))
        wanted = set()
        for h in health:
            ss = str(h.get("subsystem") or "")
            if not ss:
                continue
            wanted.add(ss)
            vals = (
                str(h.get("status") or ""),
                str(h.get("message") or ""),
                str(h.get("consecutive_failures") or 0),
                (f'{float(h.get("latency_ms") or 0.0):.0f}ms' if h.get("latency_ms") is not None else "—"),
            )
            if ss in existing:
                self._tree.item(ss, values=vals)
            else:
                self._tree.insert("", "end", iid=ss, values=vals)
        for iid in existing - wanted:
            try:
                self._tree.delete(iid)
            except Exception:
                pass

        # resources
        self._resources.configure(state="normal")
        self._resources.delete("1.0", "end")
        self._resources.insert("end", json.dumps(snap.get("resources") or {}, indent=2, ensure_ascii=False))
        self._resources.configure(state="disabled")

        # events
        self._events.configure(state="normal")
        self._events.delete("1.0", "end")
        for ev in (snap.get("recent_events") or [])[:50]:
            try:
                self._events.insert("end", json.dumps(ev, ensure_ascii=False) + "\n")
            except Exception:
                continue
        self._events.configure(state="disabled")

