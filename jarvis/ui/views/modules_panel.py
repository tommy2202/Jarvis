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

        header = ttk.Frame(self)
        header.grid(row=0, column=0, sticky="ew")
        ttk.Label(header, text="Modules").grid(row=0, column=0, sticky="w")
        ttk.Button(header, text="Scan Modules", command=self._on_scan).grid(row=0, column=1, padx=(10, 0), sticky="e")
        header.columnconfigure(0, weight=1)

        cols = ("module_id", "installed", "enabled", "requires_admin", "reason")
        self._tree = ttk.Treeview(self, columns=cols, show="headings", height=8)
        for c in cols:
            self._tree.heading(c, text=c)
            self._tree.column(c, width=140 if c == "reason" else 110, stretch=True)
        self._tree.grid(row=1, column=0, sticky="nsew", pady=(6, 0))

        btns = ttk.Frame(self)
        btns.grid(row=2, column=0, sticky="ew", pady=(6, 0))
        ttk.Button(btns, text="Enable", command=lambda: self._toggle_selected(True)).grid(row=0, column=0, padx=(0, 6))
        ttk.Button(btns, text="Disable", command=lambda: self._toggle_selected(False)).grid(row=0, column=1)
        btns.columnconfigure(2, weight=1)

        self.columnconfigure(0, weight=1)
        self.rowconfigure(1, weight=1)

    def set_snapshot(self, payload: dict) -> None:
        mods = (payload or {}).get("modules") if isinstance(payload, dict) else {}
        if not isinstance(mods, dict):
            mods = {}
        # clear
        for iid in self._tree.get_children():
            self._tree.delete(iid)
        for mid in sorted(mods.keys()):
            r = mods.get(mid) or {}
            self._tree.insert(
                "",
                "end",
                iid=mid,
                values=(
                    mid,
                    bool(r.get("installed", False)),
                    bool(r.get("enabled", False)),
                    bool(r.get("requires_admin_to_enable", False)),
                    str(r.get("reason") or "")[:120],
                ),
            )

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

