from __future__ import annotations

from tkinter import ttk


class JobsPanel(ttk.Frame):
    def __init__(self, master, *, on_cancel, on_view):  # noqa: ANN001
        super().__init__(master, padding=(8, 6))
        self._on_cancel = on_cancel
        self._on_view = on_view

        self._tree = ttk.Treeview(self, columns=("kind", "status", "progress"), show="headings", height=6)
        self._tree.heading("kind", text="Kind")
        self._tree.heading("status", text="Status")
        self._tree.heading("progress", text="Progress")
        self._tree.column("kind", width=220, anchor="w")
        self._tree.column("status", width=90, anchor="w")
        self._tree.column("progress", width=80, anchor="e")
        self._tree.grid(row=0, column=0, columnspan=2, sticky="nsew")

        y = ttk.Scrollbar(self, orient="vertical", command=self._tree.yview)
        self._tree.configure(yscrollcommand=y.set)
        y.grid(row=0, column=2, sticky="ns")

        self._cancel = ttk.Button(self, text="Cancel job", command=self._cancel_selected)
        self._view = ttk.Button(self, text="View details", command=self._view_selected)
        self._cancel.grid(row=1, column=0, sticky="w", pady=(6, 0))
        self._view.grid(row=1, column=1, sticky="e", pady=(6, 0))

        self._status = ttk.Label(self, text="")
        self._status.grid(row=2, column=0, columnspan=3, sticky="w", pady=(4, 0))

        self.columnconfigure(0, weight=1)
        self.columnconfigure(1, weight=1)
        self.rowconfigure(0, weight=1)

    def _selected_job_id(self) -> str | None:
        sel = self._tree.selection()
        if not sel:
            return None
        return str(sel[0])

    def _cancel_selected(self) -> None:
        jid = self._selected_job_id()
        if jid:
            self._on_cancel(jid)

    def _view_selected(self) -> None:
        jid = self._selected_job_id()
        if jid:
            self._on_view(jid)

    def set_jobs(self, jobs: list[dict]) -> None:
        existing = set(self._tree.get_children(""))
        wanted = set()
        for j in jobs:
            jid = str(j.get("id") or "")
            if not jid:
                continue
            wanted.add(jid)
            vals = (str(j.get("kind") or ""), str(j.get("status") or ""), f'{int(j.get("progress") or 0)}%')
            if jid in existing:
                self._tree.item(jid, values=vals)
            else:
                self._tree.insert("", "end", iid=jid, values=vals)
        # remove stale
        for iid in existing - wanted:
            try:
                self._tree.delete(iid)
            except Exception:
                pass

    def set_admin_enabled(self, is_admin: bool) -> None:
        self._cancel.configure(state=("normal" if is_admin else "disabled"))
        self._status.configure(text=("" if is_admin else "Admin required to cancel jobs."))

