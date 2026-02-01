from __future__ import annotations

"""
Module discovery (no-import scanning).

WHY THIS FILE EXISTS:
Jarvis must detect modules on disk without importing/executing Python code.
Discovery reads only manifest text and filesystem metadata.
"""

import json
import os
from dataclasses import dataclass
from typing import Any, Dict, Optional

from jarvis.core.modules.fingerprints import contract_hash_from_manifest_dict, fingerprint_module, list_files_for_fingerprint
from jarvis.core.modules.import_guard import DiscoveryImportGuard


@dataclass(frozen=True)
class DiscoveredModule:
    module_id: str
    module_dir: str
    manifest_path: str
    manifest_raw: Optional[Dict[str, Any]]
    manifest_bytes: Optional[bytes]
    fingerprint: str
    contract_hash: str
    manifest_valid: bool
    manifest_error: str = ""


class ModuleDiscovery:
    def __init__(self, *, modules_root: str):
        self.modules_root = str(modules_root)

    def scan(self) -> Dict[str, DiscoveredModule]:
        out: Dict[str, DiscoveredModule] = {}
        if not os.path.isdir(self.modules_root):
            return out

        with DiscoveryImportGuard(modules_root=self.modules_root):
            for name in sorted(os.listdir(self.modules_root)):
                if name.startswith(".") or name.startswith("_"):
                    continue
                mod_dir = os.path.join(self.modules_root, name)
                if not os.path.isdir(mod_dir):
                    continue
                if name == "__pycache__":
                    continue

                manifest_path = os.path.join(mod_dir, "module.json")
                manifest_raw = None
                manifest_bytes = None
                manifest_valid = False
                manifest_error = ""
                contract_hash = ""

                if os.path.exists(manifest_path) and os.path.isfile(manifest_path):
                    try:
                        with open(manifest_path, "rb") as f:
                            manifest_bytes = f.read()
                        manifest_raw = json.loads(manifest_bytes.decode("utf-8"))
                        if isinstance(manifest_raw, dict):
                            # Validate minimally without importing: module_id must match folder name.
                            if str(manifest_raw.get("module_id") or "") != name:
                                raise ValueError("module_id does not match folder name")
                            contract_hash = contract_hash_from_manifest_dict(manifest_raw)
                            manifest_valid = True
                        else:
                            raise ValueError("manifest is not an object")
                    except Exception as e:
                        manifest_raw = manifest_raw if isinstance(manifest_raw, dict) else None
                        manifest_valid = False
                        manifest_error = str(e)
                        try:
                            if isinstance(manifest_raw, dict):
                                contract_hash = contract_hash_from_manifest_dict(manifest_raw)
                        except Exception:
                            contract_hash = ""
                else:
                    manifest_valid = False
                    manifest_error = "module.json missing"

                files = list_files_for_fingerprint(mod_dir)
                fp = fingerprint_module(module_dir=mod_dir, manifest_bytes=manifest_bytes, file_entries=files)

                out[name] = DiscoveredModule(
                    module_id=name,
                    module_dir=mod_dir,
                    manifest_path=manifest_path,
                    manifest_raw=manifest_raw,
                    manifest_bytes=manifest_bytes,
                    fingerprint=fp,
                    contract_hash=contract_hash,
                    manifest_valid=manifest_valid,
                    manifest_error=manifest_error[:200],
                )

        return out

