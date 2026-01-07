from __future__ import annotations

import json
import os
import threading
from typing import Any, Dict, Iterable, List, Optional, Tuple

from jarvis.core.audit.hasher import chain_record


class AuditJsonlStore:
    def __init__(self, *, path: str, head_path: str):
        self.path = path
        self.head_path = head_path
        self._lock = threading.Lock()
        os.makedirs(os.path.dirname(path), exist_ok=True)
        os.makedirs(os.path.dirname(head_path), exist_ok=True)

    def read_head_hash(self) -> str:
        try:
            with open(self.head_path, "r", encoding="utf-8") as f:
                obj = json.load(f)
            return str(obj.get("head_hash") or "0" * 64)
        except Exception:
            return "0" * 64

    def write_head_hash(self, head_hash: str) -> None:
        tmp = self.head_path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump({"head_hash": head_hash}, f, indent=2, ensure_ascii=False)
            f.write("\n")
        os.replace(tmp, self.head_path)

    def append(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """
        Appends a record with hash chaining.
        payload must NOT include prev_hash/hash (they are added here).
        Returns the stored record.
        """
        with self._lock:
            prev = self.read_head_hash()
            rec = chain_record(payload=payload, prev_hash=prev)
            with open(self.path, "a", encoding="utf-8") as f:
                f.write(json.dumps(rec, ensure_ascii=False) + "\n")
            self.write_head_hash(str(rec["hash"]))
            return rec

    def iter_lines(self) -> Iterable[Dict[str, Any]]:
        if not os.path.exists(self.path):
            return []
        def _gen():
            with open(self.path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        obj = json.loads(line)
                    except Exception:
                        continue
                    if isinstance(obj, dict):
                        yield obj
        return _gen()

    def tail(self, n: int = 200) -> List[Dict[str, Any]]:
        if not os.path.exists(self.path):
            return []
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                lines = f.readlines()
            out: List[Dict[str, Any]] = []
            for line in lines[-max(1, int(n)) :]:
                try:
                    obj = json.loads(line)
                except Exception:
                    continue
                if isinstance(obj, dict):
                    out.append(obj)
            return out
        except Exception:
            return []

