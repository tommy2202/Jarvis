from __future__ import annotations

import tkinter as tk
from tkinter import ttk

from jarvis.ui.ui_models import UiConfig
from jarvis.ui.views.main_window import MainWindow


def run_desktop_ui(*, runtime, config, logger) -> None:  # noqa: ANN001
    """
    Start Tkinter UI as a thin client over Jarvis runtime.
    """
    # Convert pydantic model (config.get().ui) to simple UiConfig for UI-side typing.
    try:
        cfg = UiConfig(
            refresh_interval_ms=int(getattr(config, "refresh_interval_ms", 350)),
            max_log_entries_displayed=int(getattr(config, "max_log_entries_displayed", 200)),
            theme=str(getattr(config, "theme", "light")),
            confirm_on_exit=bool(getattr(config, "confirm_on_exit", True)),
        )
    except Exception:
        cfg = UiConfig()

    root = tk.Tk()
    try:
        style = ttk.Style(root)
        # Keep theme selection best-effort; Tk themes differ by OS.
        if cfg.theme == "dark":
            try:
                style.theme_use("clam")
            except Exception:
                pass
        else:
            try:
                style.theme_use("vista" if "vista" in style.theme_names() else style.theme_use())
            except Exception:
                pass

        app = MainWindow(root, core=runtime, config=cfg, logger=logger)

        def on_close() -> None:
            try:
                if cfg.confirm_on_exit:
                    from tkinter import messagebox

                    if not messagebox.askokcancel("Exit", "Exit Jarvis Desktop? This will shut down Jarvis core."):
                        return
                runtime.request_shutdown()
            except Exception:
                pass
            try:
                root.destroy()
            except Exception:
                pass

        root.protocol("WM_DELETE_WINDOW", on_close)
        root.geometry("1100x760")
        root.mainloop()
    finally:
        try:
            root.destroy()
        except Exception:
            pass

