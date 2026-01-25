from __future__ import annotations

import json
import os
import traceback
from contextlib import redirect_stderr, redirect_stdout


def _load_request(path: str) -> dict:
    if not os.path.exists(path):
        raise FileNotFoundError("request.json missing")
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, dict):
        raise ValueError("request.json invalid")
    return data


def _write_result(path: str, payload: dict) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload, f, ensure_ascii=False)


def main() -> int:
    work_dir = "/work"
    req_path = os.path.join(work_dir, "request.json")
    res_path = os.path.join(work_dir, "result.json")
    out_path = os.path.join(work_dir, "stdout.log")
    err_path = os.path.join(work_dir, "stderr.log")

    with open(out_path, "w", encoding="utf-8") as outf, open(err_path, "w", encoding="utf-8") as errf:
        with redirect_stdout(outf), redirect_stderr(errf):
            try:
                req = _load_request(req_path)
                module_path = str(req.get("module_path") or "").strip()
                if not module_path:
                    raise RuntimeError("module_path missing")
                intent_id = str(req.get("intent_id") or "")
                args = req.get("args") or {}
                context = req.get("context") or {}

                import importlib

                mod = importlib.import_module(module_path)
                handler = getattr(mod, "handle", None)
                if not callable(handler):
                    raise RuntimeError(f"{module_path} missing handle()")
                out = handler(intent_id=intent_id, args=args, context=context)
                _write_result(res_path, {"ok": True, "output": out})
                return 0
            except Exception as e:
                _write_result(res_path, {"ok": False, "error": str(e)[:300], "traceback": traceback.format_exc()})
                return 2


if __name__ == "__main__":
    raise SystemExit(main())
