from __future__ import annotations

import ipaddress
import json
import secrets
import socketserver
import threading
import time
from typing import Any, Dict, Optional

from jarvis.core.broker.interface import ToolBroker, ToolResult
from jarvis.core.capabilities.models import RequestContext, RequestSource
from jarvis.core.events import EventLogger, redact
from jarvis.core.events.models import BaseEvent, EventSeverity, SourceSubsystem
from jarvis.core.policy.models import PolicyContext
from jarvis.core.privacy.gates import persistence_context
from jarvis.core.privacy.redaction import privacy_redact
from jarvis.core.security_events import SecurityAuditLogger


DEFAULT_ALLOWED_CLIENT_CIDRS = ["127.0.0.1/32", "::1/128"]


class _BrokerTCPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True


class _BrokerHandler(socketserver.StreamRequestHandler):
    def handle(self) -> None:  # noqa: D401
        raw = self.rfile.readline(65536)
        if not raw:
            return
        try:
            payload = json.loads(raw.decode("utf-8"))
        except Exception:
            self._send(ToolResult(allowed=False, reason_code="INVALID_PAYLOAD", trace_id="tool", error="invalid_payload", denied_by="broker"))
            return
        broker = getattr(self.server, "broker", None)
        if broker is None:
            self._send(ToolResult(allowed=False, reason_code="BROKER_UNAVAILABLE", trace_id="tool", error="broker_unavailable", denied_by="broker"))
            return
        res = broker.handle_call(payload, client_host=str(self.client_address[0]))
        self._send(res)

    def _send(self, res: ToolResult) -> None:
        try:
            payload = res.model_dump()
            self.wfile.write((json.dumps(payload, ensure_ascii=False) + "\n").encode("utf-8"))
        except Exception:
            return


class BrokerServer:
    def __init__(
        self,
        *,
        tool_broker: ToolBroker,
        capability_engine: Any = None,
        policy_engine: Any = None,
        security_manager: Any = None,
        event_logger: Optional[EventLogger] = None,
        event_bus: Any = None,
        logger: Any = None,
        token_ttl_seconds: float = 30.0,
        bind_host: str = "127.0.0.1",
        allowed_client_cidrs: Optional[list[str]] = None,
        audit_logger: Optional[SecurityAuditLogger] = None,
    ):
        self._tool_broker = tool_broker
        self._capability_engine = capability_engine
        self._policy_engine = policy_engine
        self._security = security_manager
        self._event_logger = event_logger
        self._event_bus = event_bus
        self._logger = logger
        self._token_ttl = float(token_ttl_seconds)
        self._bind_host = str(bind_host or "127.0.0.1")
        self._allowed_client_cidrs = self._coerce_allowed_client_cidrs(allowed_client_cidrs)
        self._allowed_client_networks: list[ipaddress._BaseNetwork] = []
        self._cidrs_validated = False
        self._audit_logger = audit_logger or SecurityAuditLogger()
        self._server: Optional[_BrokerTCPServer] = None
        self._thread: Optional[threading.Thread] = None
        self._token: str = ""
        self._expires_at: float = 0.0

    def start(self) -> Dict[str, Any]:
        if self._server is not None:
            return {"host": self._bind_host, "port": int(self._server.server_address[1]), "token": self._token, "expires_at": self._expires_at}
        self._ensure_allowed_client_networks()
        self._token = secrets.token_urlsafe(24)
        self._expires_at = time.time() + max(1.0, self._token_ttl)
        self._server = _BrokerTCPServer((self._bind_host, 0), _BrokerHandler)
        self._server.broker = self  # type: ignore[attr-defined]
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        return {"host": self._bind_host, "port": int(self._server.server_address[1]), "token": self._token, "expires_at": self._expires_at}

    def stop(self) -> None:
        if self._server is None:
            return
        try:
            self._server.shutdown()
            self._server.server_close()
        except Exception:
            pass
        self._server = None
        self._token = ""
        self._expires_at = 0.0
        if self._thread is not None:
            try:
                self._thread.join(timeout=1.0)
            except Exception:
                pass
        self._thread = None

    def handle_call(self, payload: Dict[str, Any], *, client_host: str) -> ToolResult:
        trace_id = str(payload.get("trace_id") or "")
        token = str(payload.get("token") or "")
        tool_name = str(payload.get("tool_name") or "")
        tool_args = payload.get("tool_args")
        if tool_args is None:
            tool_args = payload.get("args") or {}
        if not isinstance(tool_args, dict):
            tool_args = {}
        args_keys = sorted(list(tool_args.keys()))[:50]
        requested_caps = payload.get("requested_caps") or []
        if not isinstance(requested_caps, list):
            requested_caps = []
        requested_caps = [str(c) for c in requested_caps if str(c or "").strip()]
        context = payload.get("context") or {}
        if not isinstance(context, dict):
            context = {}
        context_keys = sorted(list(context.keys()))[:50]
        if not trace_id:
            trace_id = str(context.get("trace_id") or "tool")

        allowed, reason_code = self._check_client_allowed(client_host)
        if not allowed:
            res = ToolResult(allowed=False, reason_code=reason_code, trace_id=trace_id or "tool", error="client_not_allowed", denied_by="auth")
            self._audit(trace_id or "tool", tool_name, requested_caps, res, args_keys=args_keys, context_keys=context_keys)
            return res
        if not token or token != self._token:
            res = ToolResult(allowed=False, reason_code="TOKEN_INVALID", trace_id=trace_id or "tool", error="token_invalid", denied_by="auth")
            self._audit(trace_id or "tool", tool_name, requested_caps, res, args_keys=args_keys, context_keys=context_keys)
            return res
        if time.time() > self._expires_at:
            res = ToolResult(allowed=False, reason_code="TOKEN_EXPIRED", trace_id=trace_id or "tool", error="token_expired", denied_by="auth")
            self._audit(trace_id or "tool", tool_name, requested_caps, res, args_keys=args_keys, context_keys=context_keys)
            return res

        auth_res = self._authorize(trace_id, requested_caps, context)
        if not auth_res.allowed:
            self._audit(trace_id, tool_name, requested_caps, auth_res, args_keys=args_keys, context_keys=context_keys)
            return auth_res

        ctx = dict(context or {})
        ctx["trace_id"] = trace_id
        ctx["requested_caps"] = list(requested_caps or [])
        ctx["tool_name"] = tool_name
        ephemeral = bool(ctx.get("ephemeral", False))
        try:
            if ephemeral:
                with persistence_context(persist_allowed=False):
                    res = self._tool_broker.run(tool_name, tool_args, ctx)
            else:
                res = self._tool_broker.run(tool_name, tool_args, ctx)
        except Exception as e:  # noqa: BLE001
            res = ToolResult(allowed=False, reason_code="TOOL_ERROR", trace_id=trace_id, error=str(e)[:200], denied_by="broker")
        self._audit(trace_id, tool_name, requested_caps, res, args_keys=args_keys, context_keys=context_keys)
        return res

    def _authorize(self, trace_id: str, requested_caps: list[str], context: Dict[str, Any]) -> ToolResult:
        if self._capability_engine is None:
            return ToolResult(allowed=False, reason_code="CAPABILITY_ENGINE_MISSING", trace_id=trace_id, error="capability_engine_missing", denied_by="capabilities")
        safe_mode = bool(context.get("safe_mode", False))
        shutting_down = bool(context.get("shutting_down", False))
        user_id = str(context.get("user_id") or "default")
        is_admin = bool(context.get("is_admin", False))
        secure_mode = None
        try:
            if self._security is not None and getattr(self._security, "secure_store", None) is not None:
                st = self._security.secure_store.status()
                secure_mode = str(getattr(st, "mode").value if hasattr(getattr(st, "mode"), "value") else getattr(st, "mode"))
        except Exception:
            secure_mode = None
        source_s = str(context.get("source") or "system").lower()
        try:
            source = RequestSource(source_s) if source_s in {s.value for s in RequestSource} else RequestSource.system
        except Exception:
            source = RequestSource.system

        ctx = RequestContext(
            trace_id=trace_id,
            source=source,
            user_id=user_id,
            is_admin=bool(is_admin),
            safe_mode=bool(safe_mode),
            shutting_down=bool(shutting_down),
            subsystem_health={},
            intent_id="system.tool.call",
            resource_intensive=bool("CAP_HEAVY_COMPUTE" in requested_caps),
            network_requested=bool("CAP_NETWORK_ACCESS" in requested_caps),
            extra_required_capabilities=list(requested_caps or []),
            secure_store_mode=secure_mode,
            confirmed=False,
        )
        dec = self._capability_engine.evaluate(ctx)
        if not bool(dec.allowed):
            return ToolResult(
                allowed=False,
                reason_code="CAPABILITY_DENIED",
                trace_id=trace_id,
                error=str(dec.remediation or "capability_denied")[:200],
                denied_by="capabilities",
                remediation=str(dec.remediation or "")[:200],
            )

        if self._policy_engine is not None:
            try:
                pctx = PolicyContext(
                    trace_id=trace_id,
                    intent_id=ctx.intent_id,
                    required_capabilities=list(requested_caps or []),
                    source=ctx.source.value,
                    client_id=None,
                    client_ip=None,
                    is_admin=bool(ctx.is_admin),
                    safe_mode=bool(ctx.safe_mode),
                    shutting_down=bool(ctx.shutting_down),
                    secure_store_mode=ctx.secure_store_mode,
                    tags=[],
                    resource_over_budget=None,
                    confirmed=False,
                )
                pdec = self._policy_engine.evaluate(pctx)
                if not bool(pdec.allowed):
                    return ToolResult(
                        allowed=False,
                        reason_code="POLICY_DENIED",
                        trace_id=trace_id,
                        error=str(pdec.remediation or pdec.final_reason or "policy_denied")[:200],
                        denied_by="policy",
                        remediation=str(pdec.remediation or "")[:200],
                    )
            except Exception:
                return ToolResult(allowed=False, reason_code="POLICY_ENGINE_ERROR", trace_id=trace_id, error="policy_engine_error", denied_by="policy")
        return ToolResult(allowed=True, reason_code="ALLOWED", trace_id=trace_id)

    def _audit(
        self,
        trace_id: str,
        tool_name: str,
        requested_caps: list[str],
        res: ToolResult,
        *,
        args_keys: Optional[list[str]] = None,
        context_keys: Optional[list[str]] = None,
    ) -> None:
        details = {
            "tool_name": str(tool_name or ""),
            "allowed": bool(res.allowed),
            "reason_code": str(res.reason_code or ""),
            "requested_caps": list(requested_caps or []),
            "args_keys": list(args_keys or []),
            "context_keys": list(context_keys or []),
            "denied_by": str(res.denied_by or ""),
        }
        safe_details = privacy_redact(details)
        if self._event_logger is not None:
            self._event_logger.log(trace_id, "broker.tool.call", redact(safe_details))
        if self._audit_logger is not None:
            try:
                self._audit_logger.log(
                    trace_id=trace_id,
                    severity="INFO" if res.allowed else "WARN",
                    event="broker.tool.call",
                    ip=None,
                    endpoint=str(tool_name or "tool"),
                    outcome="allowed" if res.allowed else "denied",
                    details=safe_details,
                )
            except Exception:
                pass
        if self._event_bus is not None:
            try:
                self._event_bus.publish_nowait(
                    BaseEvent(
                        event_type="broker.tool.call",
                        trace_id=trace_id,
                        source_subsystem=SourceSubsystem.dispatcher,
                        severity=EventSeverity.INFO if res.allowed else EventSeverity.WARN,
                        payload=safe_details,
                    )
                )
            except Exception:
                pass

    def _coerce_allowed_client_cidrs(self, cidrs: Optional[list[str]]) -> list[str]:
        if cidrs is None:
            return list(DEFAULT_ALLOWED_CLIENT_CIDRS)
        if isinstance(cidrs, str):
            return [cidrs]
        if isinstance(cidrs, (list, tuple, set)):
            return [str(item) for item in cidrs]
        raise ValueError("allowed_client_cidrs must be a list of CIDR strings")

    def _ensure_allowed_client_networks(self) -> None:
        if self._cidrs_validated:
            return
        networks: list[ipaddress._BaseNetwork] = []
        for raw in self._allowed_client_cidrs:
            cidr = str(raw or "").strip()
            if not cidr:
                raise ValueError("allowed_client_cidrs contains an empty CIDR")
            try:
                networks.append(ipaddress.ip_network(cidr, strict=False))
            except ValueError as exc:
                raise ValueError(f"Invalid CIDR: {cidr}") from exc
        self._allowed_client_networks = networks
        self._cidrs_validated = True

    def _check_client_allowed(self, client_host: str) -> tuple[bool, str]:
        allowed = self._is_allowed_client(client_host)
        return allowed, "ALLOWED" if allowed else "CLIENT_NOT_ALLOWED"

    def _is_allowed_client(self, client_host: str) -> bool:
        self._ensure_allowed_client_networks()
        try:
            ip = ipaddress.ip_address(str(client_host))
        except ValueError:
            return False
        for network in self._allowed_client_networks:
            if ip in network:
                return True
        return False
