from __future__ import annotations

"""
Modules panel (UI) for scanning and enable/disable toggles.

WHY THIS FILE EXISTS:
The desktop UI must be able to trigger a safe module scan and display installed
module status without importing/executing module handlers. Mutating operations
are delegated to JarvisRuntime and remain admin-gated there.
"""

from tkinter import ttk


class ModulesPanel(ttk.Frame):
    def __init__(self, master, *, on_scan, on_toggle):  # noqa: ANN001
        super().__init__(master, padding=(8, 6))
        self._on_scan = on_scan
        self._on_toggle = on_toggle
        self._by_id: dict[str, dict] = {}

        header = ttk.Frame(self)
        header.grid(row=0, column=0, sticky="ew")
        ttk.Label(header, text="Modules").grid(row=0, column=0, sticky="w")
        ttk.Button(header, text="Scan Modules", command=self._on_scan).grid(row=0, column=1, padx=(10, 0), sticky="e")
        header.columnconfigure(0, weight=1)

        cols = ("module_id", "state", "enabled", "reason_code", "remediation")
        self._tree = ttk.Treeview(self, columns=cols, show="headings", height=8)
        for c in cols:
            self._tree.heading(c, text=c)
            self._tree.column(c, width=220 if c in {"remediation"} else 140 if c in {"state"} else 120, stretch=True)
        self._tree.grid(row=1, column=0, sticky="nsew", pady=(6, 0))
        self._tree.bind("<<TreeviewSelect>>", self._on_select)

        details = ttk.Frame(self)
        details.grid(row=2, column=0, sticky="ew", pady=(6, 0))
        self._detail_reason = ttk.Label(details, text="", wraplength=700, justify="left")
        self._detail_remediation = ttk.Label(details, text="", wraplength=700, justify="left")
        self._detail_reason.grid(row=0, column=0, sticky="w")
        self._detail_remediation.grid(row=1, column=0, sticky="w", pady=(2, 0))
        details.columnconfigure(0, weight=1)

        btns = ttk.Frame(self)
        btns.grid(row=3, column=0, sticky="ew", pady=(6, 0))
        ttk.Button(btns, text="Enable", command=lambda: self._toggle_selected(True)).grid(row=0, column=0, padx=(0, 6))
        ttk.Button(btns, text="Disable", command=lambda: self._toggle_selected(False)).grid(row=0, column=1, padx=(0, 6))
        ttk.Button(btns, text="Repair", state="disabled").grid(row=0, column=2)  # Repair flow implemented in core later.
        btns.columnconfigure(3, weight=1)

        self.columnconfigure(0, weight=1)
        self.rowconfigure(1, weight=1)

    def set_snapshot(self, payload: dict) -> None:
        self._by_id = {}
        statuses = (payload or {}).get("statuses") if isinstance(payload, dict) else None
        if isinstance(statuses, list):
            for s in statuses:
                if isinstance(s, dict) and s.get("module_id"):
                    self._by_id[str(s.get("module_id"))] = dict(s)
        else:
            # Backwards-compat: derive minimal rows from legacy registry dict.
            mods = (payload or {}).get("modules") if isinstance(payload, dict) else {}
            if not isinstance(mods, dict):
                mods = {}
            for mid in sorted(mods.keys()):
                r = mods.get(mid) or {}
                self._by_id[str(mid)] = {
                    "module_id": str(mid),
                    "state": "UNKNOWN",
                    "reason_code": "UNKNOWN",
                    "remediation": "",
                    "reason_human": str(r.get("reason") or "")[:120],
                    "enabled": bool(r.get("enabled", False)),
                }
        # clear
        for iid in self._tree.get_children():
            self._tree.delete(iid)
        for mid in sorted(self._by_id.keys()):
            r = self._by_id.get(mid) or {}
            enabled = bool(r.get("enabled", False))
            self._tree.insert(
                "",
                "end",
                iid=mid,
                values=(
                    mid,
                    str(r.get("state") or ""),
                    enabled,
                    str(r.get("reason_code") or ""),
                    str(r.get("remediation") or "")[:120],
                ),
            )
        self._set_details(None)

    def _set_details(self, module_id: str | None) -> None:
        if not module_id or module_id not in self._by_id:
            self._detail_reason.configure(text="")
            self._detail_remediation.configure(text="")
            return
        r = self._by_id.get(module_id) or {}
        state = str(r.get("state") or "")
        rc = str(r.get("reason_code") or "")
        why = str(r.get("reason_human") or "")
        rem = str(r.get("remediation") or "")
        self._detail_reason.configure(text=(f"State: {state} ({rc}) — {why}" if (state or rc or why) else ""))
        self._detail_remediation.configure(text=(f"Remediation: {rem}" if rem else ""))

    def _on_select(self, _ev=None):  # noqa: ANN001
        self._set_details(self._selected_module_id())

    def _selected_module_id(self) -> str | None:
        sel = self._tree.selection()
        if not sel:
            return None
        return str(sel[0])

    def _toggle_selected(self, enable: bool) -> None:
        mid = self._selected_module_id()
        if not mid:
            return
        self._on_toggle(mid, enable)

