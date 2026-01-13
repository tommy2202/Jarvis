"""
Module contract + setup wizard infrastructure.

WHY THIS PACKAGE EXISTS:
Jarvis must be able to discover modules on disk without importing/executing their
Python code, validate/repair their manifests, and enforce install+enable gates
before dispatch. This is core security infrastructure (no feature modules).
"""

from jarvis.core.modules.manager import ModuleManager

__all__ = ["ModuleManager"]

