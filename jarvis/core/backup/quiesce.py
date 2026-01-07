from __future__ import annotations

from contextlib import contextmanager
from typing import Any, Dict, Iterator, Optional


@contextmanager
def quiesce(*, config_manager: Any = None, secure_store: Any = None, runtime_state: Any = None) -> Iterator[Dict[str, Any]]:
    """
    Best-effort quiesce for consistent snapshots.
    - pauses config writes (if supported)
    - pauses secure store writes (if supported)
    - forces runtime_state save (if available)
    """
    token_cfg = None
    token_sec = None
    info: Dict[str, Any] = {"config_paused": False, "secure_paused": False, "runtime_saved": False}
    try:
        if config_manager is not None and hasattr(config_manager, "pause_writes"):
            token_cfg = config_manager.pause_writes()
            info["config_paused"] = True
    except Exception:
        pass
    try:
        if secure_store is not None and hasattr(secure_store, "pause_writes"):
            token_sec = secure_store.pause_writes()
            info["secure_paused"] = True
    except Exception:
        pass
    try:
        if runtime_state is not None and hasattr(runtime_state, "save"):
            runtime_state.save(reason="backup")
            info["runtime_saved"] = True
    except Exception:
        pass
    try:
        yield info
    finally:
        try:
            if secure_store is not None and token_sec is not None and hasattr(secure_store, "resume_writes"):
                secure_store.resume_writes(token_sec)
        except Exception:
            pass
        try:
            if config_manager is not None and token_cfg is not None and hasattr(config_manager, "resume_writes"):
                config_manager.resume_writes(token_cfg)
        except Exception:
            pass

