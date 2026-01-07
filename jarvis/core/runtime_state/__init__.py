"""
Persistent runtime state (operational state, not chat memory).

Stored under runtime/ with atomic writes, backups, and corruption recovery.
"""

from jarvis.core.runtime_state.manager import RuntimeStateManager

__all__ = ["RuntimeStateManager"]

