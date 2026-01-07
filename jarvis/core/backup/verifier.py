from __future__ import annotations

import io
import json
import zipfile
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

from jarvis.core.backup.hasher import sha256_bytes, sha256_stream


@dataclass(frozen=True)
class VerifyResult:
    ok: bool
    errors: List[str]
    checked_files: int


def verify_zip(zip_path: str) -> VerifyResult:
    errors: List[str] = []
    checked = 0
    with zipfile.ZipFile(zip_path, "r") as z:
        try:
            manifest_bytes = z.read("manifest.json")
        except KeyError:
            return VerifyResult(ok=False, errors=["missing manifest.json"], checked_files=0)
        try:
            man = json.loads(manifest_bytes.decode("utf-8"))
        except Exception as e:
            return VerifyResult(ok=False, errors=[f"invalid manifest.json: {e}"], checked_files=0)
        try:
            sig = z.read("manifest.sha256").decode("utf-8").strip()
            if sig != sha256_bytes(manifest_bytes):
                errors.append("manifest.sha256 mismatch")
        except Exception:
            errors.append("missing manifest.sha256")

        contents = man.get("contents") or []
        for ent in contents:
            rel = ent.get("relative_path")
            exp_hash = ent.get("sha256")
            exp_size = int(ent.get("size_bytes") or 0)
            if not rel or rel in {"manifest.json", "manifest.sha256"}:
                continue
            try:
                with z.open(rel, "r") as fp:
                    data_hash = sha256_stream(fp)
                info = z.getinfo(rel)
                if int(info.file_size) != exp_size:
                    errors.append(f"size mismatch: {rel}")
                if data_hash != exp_hash:
                    errors.append(f"hash mismatch: {rel}")
                checked += 1
            except KeyError:
                errors.append(f"missing file: {rel}")
            except Exception as e:
                errors.append(f"error reading {rel}: {e}")

        # Optional audit head check if both are present
        try:
            if "logs/audit/head.json" in z.namelist() and "logs/audit/audit_events.jsonl" in z.namelist():
                head = json.loads(z.read("logs/audit/head.json").decode("utf-8"))
                head_hash = str(head.get("head_hash") or "")
                # read last non-empty line of audit_events.jsonl
                data = z.read("logs/audit/audit_events.jsonl").decode("utf-8", errors="ignore").splitlines()
                last = ""
                for line in reversed(data):
                    if line.strip():
                        last = line.strip()
                        break
                if last:
                    obj = json.loads(last)
                    last_hash = str(obj.get("hash") or "")
                    if head_hash and last_hash and head_hash != last_hash:
                        errors.append("audit head hash does not match last audit record")
        except Exception:
            # best-effort
            pass

    return VerifyResult(ok=(len(errors) == 0), errors=errors, checked_files=checked)

