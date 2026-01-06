from __future__ import annotations

import json
from typing import Any


def json_depth(obj: Any, max_depth: int = 10) -> int:
    """
    Computes JSON nesting depth. Raises ValueError if max_depth exceeded.
    """
    stack = [(obj, 1)]
    seen_max = 1
    while stack:
        cur, d = stack.pop()
        if d > max_depth:
            raise ValueError("json too deeply nested")
        seen_max = max(seen_max, d)
        if isinstance(cur, dict):
            for v in cur.values():
                stack.append((v, d + 1))
        elif isinstance(cur, list):
            for v in cur:
                stack.append((v, d + 1))
    return seen_max


def enforce_body_limits(body: bytes, *, max_bytes: int) -> None:
    if body is None:
        return
    if len(body) > int(max_bytes):
        raise ValueError("request too large")
    if b"\x00" in body:
        raise ValueError("binary payload rejected")


def parse_json_body(body: bytes) -> Any:
    if not body:
        return None
    return json.loads(body.decode("utf-8"))

