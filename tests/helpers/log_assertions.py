from __future__ import annotations

import json
from typing import Any, Dict, Iterable, List


def read_jsonl(path: str) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            out.append(json.loads(line))
    return out


def assert_no_secret_leak(objs: Iterable[Dict[str, Any]], secret: str) -> None:
    blob = json.dumps(list(objs), ensure_ascii=False)
    assert secret not in blob
    assert "***REDACTED***" in blob

