from __future__ import annotations

from typing import Any, Callable, Dict, Optional

from jarvis.core.broker.interface import ToolBroker, ToolResult
from jarvis.core.privacy.redaction import privacy_redact
from jarvis.core.security_events import SecurityAuditLogger


class ToolRegistry(ToolBroker):
    def __init__(self, *, tools: Optional[Dict[str, Callable[[Dict[str, Any], Dict[str, Any]], ToolResult]]] = None, audit_logger: Optional[SecurityAuditLogger] = None):
        self._tools = dict(tools or {})
        self._audit = audit_logger or SecurityAuditLogger()

    def register(self, name: str, handler: Callable[[Dict[str, Any], Dict[str, Any]], ToolResult]) -> None:
        self._tools[str(name)] = handler

    def run(self, tool_name: str, args: Dict[str, Any], context: Dict[str, Any]) -> ToolResult:
        name = str(tool_name or "")
        trace_id = str((context or {}).get("trace_id") or "tool")
        if name not in self._tools:
            res = ToolResult(allowed=False, reason_code="TOOL_UNKNOWN", trace_id=trace_id, output=None, denied_by="registry")
            self._audit_call(name, args, context, res)
            return res
        try:
            res = self._tools[name](args or {}, context or {})
            if not isinstance(res, ToolResult):
                res = ToolResult(allowed=True, reason_code="ALLOWED", trace_id=trace_id, output={"result": res})
        except Exception as e:  # noqa: BLE001
            res = ToolResult(allowed=False, reason_code="TOOL_ERROR", trace_id=trace_id, error=str(e), denied_by="registry")
        self._audit_call(name, args, context, res)
        return res

    def _audit_call(self, tool_name: str, args: Dict[str, Any], context: Dict[str, Any], res: ToolResult) -> None:
        details = {
            "tool_name": str(tool_name),
            "allowed": bool(res.allowed),
            "reason_code": str(res.reason_code or ""),
            "args_keys": sorted(list((args or {}).keys()))[:50],
            "context_keys": sorted(list((context or {}).keys()))[:50],
        }
        self._audit.log(
            trace_id=str(res.trace_id or (context or {}).get("trace_id") or "tool"),
            severity="INFO" if res.allowed else "WARN",
            event="tool.run",
            ip=None,
            endpoint=str(tool_name or "tool"),
            outcome="allowed" if res.allowed else "denied",
            details=privacy_redact(details),
        )
