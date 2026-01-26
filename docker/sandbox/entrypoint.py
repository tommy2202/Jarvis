from __future__ import annotations

import json
import os
import socket
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


def _parse_endpoint(endpoint: str) -> tuple[str, int]:
    if endpoint.startswith("tcp://"):
        endpoint = endpoint[6:]
    if "://" in endpoint:
        endpoint = endpoint.split("://", 1)[1]
    host, port_s = endpoint.rsplit(":", 1)
    return host, int(port_s)


def _call_broker(endpoint: str, token: str, payload: dict, *, timeout: float = 5.0) -> dict:
    host, port = _parse_endpoint(endpoint)
    payload = dict(payload or {})
    payload["token"] = token
    data = json.dumps(payload, ensure_ascii=False).encode("utf-8") + b"\n"
    with socket.create_connection((host, int(port)), timeout=timeout) as sock:
        sock.sendall(data)
        resp = sock.makefile("rb").readline(65536)
    if not resp:
        return {"ok": False, "reason_code": "BROKER_NO_RESPONSE", "error": "broker_no_response"}
    try:
        return json.loads(resp.decode("utf-8").strip() or "{}")
    except Exception:
        return {"ok": False, "reason_code": "BROKER_INVALID_RESPONSE", "error": "broker_invalid_response"}


def _execute_plan(req: dict) -> dict:
    plan = req.get("execution_plan") or {}
    tool_calls = plan.get("tool_calls") or []
    if not isinstance(tool_calls, list):
        tool_calls = []
    broker_url = os.environ.get("BROKER_URL") or os.environ.get("JARVIS_BROKER_ENDPOINT") or ""
    broker_token = os.environ.get("BROKER_TOKEN") or os.environ.get("JARVIS_BROKER_TOKEN") or ""
    if not broker_url or not broker_token:
        return {"ok": False, "error": "broker_unconfigured", "output": {"reason_code": "BROKER_MISSING", "remediation": "Set BROKER_URL and BROKER_TOKEN."}}
    context = req.get("context") or {}
    if not isinstance(context, dict):
        context = {}
    trace_id = str(req.get("trace_id") or context.get("trace_id") or "tool")
    tool_results = []
    artifacts = []
    for idx, call in enumerate(tool_calls):
        if not isinstance(call, dict):
            return {
                "ok": False,
                "error": "plan_invalid",
                "output": {"reason_code": "PLAN_INVALID", "remediation": f"ToolCall at index {idx} is not a dict."},
            }
        tool_name = str(call.get("tool_name") or "")
        tool_args = call.get("tool_args")
        if tool_args is None:
            tool_args = call.get("args") or {}
        if not isinstance(tool_args, dict):
            tool_args = {}
        requested_caps = call.get("requested_caps") or []
        if not isinstance(requested_caps, list):
            requested_caps = []
        if not tool_name:
            return {
                "ok": False,
                "error": "plan_invalid",
                "output": {"reason_code": "PLAN_INVALID", "remediation": f"ToolCall at index {idx} missing tool_name."},
            }
        res = _call_broker(
            broker_url,
            broker_token,
            {
                "trace_id": trace_id,
                "tool_name": tool_name,
                "tool_args": tool_args,
                "requested_caps": requested_caps,
                "context": context,
            },
        )
        ok = bool(res.get("ok")) if "ok" in res else bool(res.get("allowed"))
        result_payload = res.get("result") if isinstance(res.get("result"), dict) else res.get("output")
        tool_results.append(
            {
                "tool_name": tool_name,
                "ok": bool(ok),
                "reason_code": str(res.get("reason_code") or ""),
                "denied_by": str(res.get("denied_by") or ""),
                "remediation": str(res.get("remediation") or ""),
                "result": result_payload if isinstance(result_payload, dict) else None,
            }
        )
        if isinstance(res.get("artifacts"), list):
            artifacts.extend(res.get("artifacts") or [])
        if not ok:
            return {
                "ok": False,
                "error": str(res.get("reason_code") or "tool_denied"),
                "output": {
                    "tool_results": tool_results,
                    "reason_code": str(res.get("reason_code") or ""),
                    "denied_by": str(res.get("denied_by") or ""),
                    "remediation": str(res.get("remediation") or ""),
                    "message": f"Tool {tool_name} denied.",
                    "artifacts": artifacts,
                },
            }
    return {
        "ok": True,
        "output": {
            "tool_results": tool_results,
            "artifacts": artifacts,
            "message": f"Executed {len(tool_results)} tool call(s).",
        },
    }


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
                if isinstance(req.get("execution_plan"), dict):
                    res = _execute_plan(req)
                    _write_result(res_path, res)
                    return 0 if bool(res.get("ok")) else 2

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
