from __future__ import annotations

import builtins
import importlib
import importlib.abc
import importlib.machinery
import importlib.util
import os
import sys
from typing import Any, Dict, Iterable, Optional


class DiscoveryImportGuard(importlib.abc.MetaPathFinder):
    """
    Guard against imports from the modules root during discovery scans.
    Raises ImportError if an import resolves inside modules_root or matches
    a derived package prefix for the modules root.
    """

    def __init__(self, *, modules_root: str):
        self.modules_root = self._normalize_root(modules_root)
        self.attempts: list[Dict[str, Optional[str]]] = []
        self._prefixes = self._derive_prefixes(self.modules_root)
        self._orig_import = None
        self._orig_import_module = None
        self._orig_exec_module = None
        self._installed = False

    def _normalize_root(self, root: str) -> str:
        if not root:
            return ""
        return os.path.abspath(str(root))

    def _derive_prefixes(self, root: str) -> set[str]:
        prefixes: set[str] = set()
        if not root:
            return prefixes
        root_norm = root.replace("\\", "/")
        if root_norm.endswith("/jarvis/modules"):
            prefixes.add("jarvis.modules")
        for base in sys.path:
            if not base:
                continue
            try:
                base_abs = os.path.abspath(str(base))
            except Exception:
                continue
            if not root.startswith(base_abs + os.sep):
                continue
            rel = os.path.relpath(root, base_abs)
            parts = [p for p in rel.split(os.sep) if p]
            if parts:
                prefixes.add(".".join(parts))
        return prefixes

    def _origin_in_root(self, origin: Optional[str]) -> bool:
        if not origin or not self.modules_root:
            return False
        origin_abs = os.path.abspath(str(origin))
        root = self.modules_root
        return origin_abs == root or origin_abs.startswith(root + os.sep)

    def _record(self, fullname: str, origin: Optional[str]) -> None:
        self.attempts.append({"module": fullname, "origin": origin})

    def _blocked_name(self, fullname: str) -> bool:
        for prefix in self._prefixes:
            if fullname == prefix or fullname.startswith(prefix + "."):
                return True
        return False

    def _block(self, fullname: str, origin: Optional[str]) -> None:
        self._record(fullname, origin)
        detail = fullname
        if origin:
            detail = f"{detail} ({origin})"
        raise ImportError(f"Import blocked during module discovery: {detail}")

    def _resolve_name(self, name: str, globals: Optional[Dict[str, Any]], level: int) -> str:
        if level and globals:
            pkg = globals.get("__package__") or globals.get("__name__") or ""
            try:
                return importlib.util.resolve_name(name, pkg)
            except Exception:
                return name
        return name

    def _check_loaded(self, fullname: str) -> None:
        mod = sys.modules.get(fullname)
        if mod is None:
            return
        origin = getattr(mod, "__file__", None)
        if origin is None:
            origin = getattr(getattr(mod, "__spec__", None), "origin", None)
        if self._origin_in_root(origin):
            self._block(fullname, origin)

    def _guarded_import(self, name: str, globals=None, locals=None, fromlist=(), level: int = 0):  # noqa: ANN001
        fullname = self._resolve_name(str(name), globals, int(level))
        if fullname:
            self._check_loaded(fullname)
            if self._blocked_name(fullname):
                self._block(fullname, None)
        return self._orig_import(name, globals, locals, fromlist, level)

    def _guarded_import_module(self, name: str, package: Optional[str] = None):
        fullname = str(name)
        if package and str(name).startswith("."):
            try:
                fullname = importlib.util.resolve_name(str(name), str(package))
            except Exception:
                fullname = str(name)
        if fullname:
            self._check_loaded(fullname)
            if self._blocked_name(fullname):
                self._block(fullname, None)
        return self._orig_import_module(name, package)

    def _guarded_exec_module(self, loader, module):  # noqa: ANN001
        origin = getattr(loader, "path", None)
        if not origin:
            origin = getattr(getattr(module, "__spec__", None), "origin", None)
        if self._origin_in_root(origin):
            self._block(getattr(module, "__name__", "unknown"), origin)
        return self._orig_exec_module(loader, module)

    def find_spec(self, fullname: str, path=None, target=None):  # noqa: ANN001
        if self._blocked_name(fullname):
            self._block(fullname, None)
        spec = importlib.machinery.PathFinder.find_spec(fullname, path, target)
        if spec is None:
            return None
        origin = getattr(spec, "origin", None)
        if self._origin_in_root(origin):
            self._block(fullname, origin)
        locations: Iterable[str] | None = getattr(spec, "submodule_search_locations", None)
        if locations:
            for loc in locations:
                if self._origin_in_root(str(loc)):
                    self._block(fullname, str(loc))
        return None

    def __enter__(self) -> "DiscoveryImportGuard":
        if self._installed:
            return self
        self._orig_import = builtins.__import__
        self._orig_import_module = importlib.import_module
        self._orig_exec_module = importlib.machinery.SourceFileLoader.exec_module
        builtins.__import__ = self._guarded_import
        importlib.import_module = self._guarded_import_module
        importlib.machinery.SourceFileLoader.exec_module = self._guarded_exec_module
        sys.meta_path.insert(0, self)
        self._installed = True
        return self

    def __exit__(self, exc_type, exc, tb) -> None:  # noqa: ANN001
        if not self._installed:
            return None
        builtins.__import__ = self._orig_import
        importlib.import_module = self._orig_import_module
        importlib.machinery.SourceFileLoader.exec_module = self._orig_exec_module
        try:
            if self in sys.meta_path:
                sys.meta_path.remove(self)
        except Exception:
            pass
        self._installed = False
        return None
