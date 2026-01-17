from __future__ import annotations

import importlib
from dataclasses import dataclass
from typing import Any, Callable, Dict, List, Optional


class ModuleLoadError(RuntimeError):
    pass


@dataclass(frozen=True)
class LoadedModule:
    module_path: str
    module_id: str
    meta: Dict[str, Any]
    _unsafe_handler: Callable[..., Any]

    @property
    def handler(self) -> Callable[..., Any]:
        """
        UNSAFE: direct handler access is disallowed.
        Use Dispatcher.execute_loaded_module(...) instead.
        """
        raise RuntimeError("LoadedModule.handler is unsafe; use Dispatcher.execute_loaded_module().")

    def _call_unsafe(self, *, intent_id: str, args: Dict[str, Any], context: Dict[str, Any]) -> Any:
        if not bool((context or {}).get("_dispatcher_execute", False)):
            raise RuntimeError("Unsafe handler call detected. Use Dispatcher.execute_loaded_module().")
        return self._unsafe_handler(intent_id=intent_id, args=args, context=context)


class ModuleRegistry:
    """
    Loads Python modules from `config/modules_registry.json`.
    Contract:
      - module defines MODULE_META (dict) with at least {"id": "<module_id>"}.
      - module defines `handle(intent_id: str, args: dict, context: dict) -> dict`.
    """

    def __init__(self) -> None:
        self._modules_by_id: Dict[str, LoadedModule] = {}
        self._modules_by_path: Dict[str, LoadedModule] = {}

    def register(self, module_path: str) -> LoadedModule:
        try:
            mod = importlib.import_module(module_path)
        except Exception as e:  # noqa: BLE001
            raise ModuleLoadError(f"Failed to import {module_path}: {e}") from e

        meta = getattr(mod, "MODULE_META", None)
        handler = getattr(mod, "handle", None)
        if not isinstance(meta, dict) or "id" not in meta:
            raise ModuleLoadError(f"{module_path} missing MODULE_META with required key 'id'.")
        if not callable(handler):
            raise ModuleLoadError(f"{module_path} missing callable handle().")

        loaded = LoadedModule(module_path=module_path, module_id=str(meta["id"]), meta=meta, _unsafe_handler=handler)
        self._modules_by_id[loaded.module_id] = loaded
        self._modules_by_path[module_path] = loaded
        return loaded

    def register_handler(self, *, module_id: str, module_path: str, meta: Dict[str, Any], handler: Callable[..., Any]) -> LoadedModule:
        """
        Register an already-resolved handler without importing module code here.

        WHY:
        Manifest-based modules use an entrypoint registration function. The module
        manager is responsible for gating enablement and invoking entrypoints;
        this registry simply stores the resulting handler.
        """
        loaded = LoadedModule(module_path=str(module_path), module_id=str(module_id), meta=dict(meta or {}), _unsafe_handler=handler)
        self._modules_by_id[loaded.module_id] = loaded
        self._modules_by_path[loaded.module_path] = loaded
        return loaded

    def get_by_id(self, module_id: str) -> Optional[LoadedModule]:
        return self._modules_by_id.get(module_id)

    def list_modules(self) -> List[LoadedModule]:
        return list(self._modules_by_id.values())

