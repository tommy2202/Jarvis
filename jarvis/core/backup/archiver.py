from __future__ import annotations

import io
import json
import os
import zipfile
from typing import Any, Dict, List, Tuple

from jarvis.core.backup.hasher import sha256_bytes


def write_zip(
    *,
    zip_path: str,
    root_dir: str,
    files: List[Tuple[str, str, bytes | None]],
    manifest: Dict[str, Any],
) -> None:
    """
    files: list of (absolute_path, relative_path_in_zip, override_bytes_or_None)
    """
    os.makedirs(os.path.dirname(zip_path) or ".", exist_ok=True)
    with zipfile.ZipFile(zip_path, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as z:
        # write files
        for abs_path, rel_path, override in files:
            if override is not None:
                z.writestr(rel_path, override)
            else:
                z.write(abs_path, arcname=rel_path)
        # write manifest
        manifest_json = json.dumps(manifest, ensure_ascii=False, indent=2, sort_keys=True).encode("utf-8")
        z.writestr("manifest.json", manifest_json)
        z.writestr("manifest.sha256", (sha256_bytes(manifest_json) + "\n").encode("utf-8"))


def read_zip_member(zip_path: str, member: str) -> bytes:
    with zipfile.ZipFile(zip_path, "r") as z:
        return z.read(member)


def list_zip(zip_path: str) -> List[str]:
    with zipfile.ZipFile(zip_path, "r") as z:
        return z.namelist()

