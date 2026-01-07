from __future__ import annotations

import time
import uuid
from typing import Any, Dict, Optional

from fastapi import Request
from fastapi.responses import JSONResponse

from jarvis.core.events import EventLogger, redact
from jarvis.core.security_events import SecurityAuditLogger
from jarvis.web.security.auth import ApiKeyStore
from jarvis.web.security.rate_limit import RateLimiter
from jarvis.web.security.request_guard import enforce_body_limits, json_depth, parse_json_body
from jarvis.web.security.strikes import LockoutConfig, StrikeManager


def _client_ip(request: Request) -> Optional[str]:
    return getattr(getattr(request, "client", None), "host", None)


def _required_scope(method: str, path: str) -> Optional[str]:
    # Public endpoints
    if path in {"/", "/health"}:
        return None
    if path == "/v1/status" or path == "/v1/llm/status":
        return "read"
    if path == "/v1/message":
        return "message"
    if path.startswith("/v1/jobs"):
        if method == "GET":
            return "read"
        return "message"
    if path == "/v1/admin/unlock":
        return "admin"
    return "read"


class WebSecurityMiddleware:
    """
    Security middleware chain (order matters):
    1) trace_id + request audit
    2) request size + JSON guard
    3) lockout checks
    4) API key auth + scopes
    5) rate limiting
    6) audit outcome
    """

    def __init__(self, *, web_cfg: Dict[str, Any], secure_store, event_logger: EventLogger, audit_logger: SecurityAuditLogger, telemetry=None):
        self.web_cfg = web_cfg
        self.event_logger = event_logger
        self.audit_logger = audit_logger
        self.telemetry = telemetry
        self.api_keys = ApiKeyStore(secure_store)
        self.rate = RateLimiter()
        self.strikes = StrikeManager(secure_store, LockoutConfig.model_validate(web_cfg.get("lockout") or {}))

    async def __call__(self, request: Request, call_next):  # noqa: ANN001
        trace_id = uuid.uuid4().hex
        request.state.trace_id = trace_id
        ip = _client_ip(request)
        path = request.url.path
        method = request.method
        client_id = request.headers.get("X-Client-Id", "")
        t0 = time.time()

        if self.telemetry is not None:
            try:
                self.telemetry.increment_counter("requests_total", 1, tags={"source": "web"})
            except Exception:
                pass

        self.audit_logger.log(trace_id=trace_id, severity="INFO", event="web.request", ip=ip, endpoint=path, outcome="received", details={"method": method, "client_id": client_id})
        self.event_logger.log(trace_id, "web.request", {"path": path, "method": method, "client_host": ip})

        # Request guard: size + JSON depth for JSON bodies
        max_bytes = int(self.web_cfg.get("max_request_bytes", 32768))
        if method in {"POST", "PUT", "PATCH"}:
            try:
                body = await request.body()
                enforce_body_limits(body, max_bytes=max_bytes)
                # Basic JSON validation; avoid recursion bombs
                ct = request.headers.get("content-type", "")
                if "application/json" in ct:
                    obj = parse_json_body(body)
                    if obj is not None:
                        json_depth(obj, max_depth=10)
            except Exception as e:
                self.strikes.record_strike(ip=ip, key_id=None)
                if self.telemetry is not None:
                    try:
                        self.telemetry.increment_counter("errors_total", 1, tags={"subsystem": "web", "severity": "WARN"})
                    except Exception:
                        pass
                self.audit_logger.log(trace_id=trace_id, severity="WARN", event="web.request_rejected", ip=ip, endpoint=path, outcome="rejected", details={"reason": str(e)})
                return JSONResponse(status_code=413 if "large" in str(e) else 400, content={"detail": "Request rejected."})

        # Lockout checks (persisted)
        if ip and self.strikes.is_ip_locked(ip):
            self.audit_logger.log(trace_id=trace_id, severity="WARN", event="web.lockout", ip=ip, endpoint=path, outcome="blocked", details={"target": "ip"})
            return JSONResponse(status_code=403, content={"detail": "Locked out."})

        required = _required_scope(method, path)
        key_id = None
        scopes = []
        if required is not None:
            provided = request.headers.get("X-API-Key", "")
            v = self.api_keys.validate(provided, ip=ip, required_scope=required)
            if not v.get("ok"):
                key_id = v.get("key_id")
                self.strikes.record_strike(ip=ip, key_id=key_id)
                if self.telemetry is not None:
                    try:
                        self.telemetry.increment_counter("auth_failures_total", 1, tags={"source": "web"})
                    except Exception:
                        pass
                self.audit_logger.log(
                    trace_id=trace_id,
                    severity="WARN",
                    event="web.auth_failed",
                    ip=ip,
                    endpoint=path,
                    outcome="denied",
                    details={"reason": v.get("reason"), "client_id": client_id, "required_scope": required},
                )
                return JSONResponse(status_code=401, content={"detail": "Unauthorized."})
            key_id = str(v.get("key_id"))
            scopes = list(v.get("scopes") or [])

            # Key lockout check
            if key_id and self.strikes.is_key_locked(key_id):
                # count lockouts -> permanent revoke handled by CLI/admin ops; here we just block.
                self.audit_logger.log(trace_id=trace_id, severity="WARN", event="web.lockout", ip=ip, endpoint=path, outcome="blocked", details={"target": "key", "key_id": key_id})
                return JSONResponse(status_code=403, content={"detail": "Locked out."})

        # Rate limiting
        rl = self.web_cfg.get("rate_limits") or {}
        per_ip = int(rl.get("per_ip_per_minute", 60))
        if ip and not self.rate.allow(f"ip:{ip}", per_minute=per_ip):
            self.strikes.record_strike(ip=ip, key_id=key_id)
            self.audit_logger.log(trace_id=trace_id, severity="WARN", event="web.rate_limited", ip=ip, endpoint=path, outcome="429", details={"scope": "ip"})
            return JSONResponse(status_code=429, content={"detail": "Rate limit exceeded."})

        if required == "message":
            per_key = int(rl.get("per_key_per_minute", 30))
            if key_id and not self.rate.allow(f"key:{key_id}:msg", per_minute=per_key):
                self.strikes.record_strike(ip=ip, key_id=key_id)
                self.audit_logger.log(trace_id=trace_id, severity="WARN", event="web.rate_limited", ip=ip, endpoint=path, outcome="429", details={"scope": "key_message", "key_id": key_id})
                return JSONResponse(status_code=429, content={"detail": "Rate limit exceeded."})

        if required == "admin":
            per_admin = int(rl.get("admin_per_minute", 5))
            if key_id and not self.rate.allow(f"key:{key_id}:admin", per_minute=per_admin):
                self.strikes.record_strike(ip=ip, key_id=key_id)
                self.audit_logger.log(trace_id=trace_id, severity="WARN", event="web.rate_limited", ip=ip, endpoint=path, outcome="429", details={"scope": "key_admin", "key_id": key_id})
                return JSONResponse(status_code=429, content={"detail": "Rate limit exceeded."})

        request.state.key_id = key_id
        request.state.scopes = scopes

        # Call downstream
        try:
            resp = await call_next(request)
            self.audit_logger.log(trace_id=trace_id, severity="INFO", event="web.response", ip=ip, endpoint=path, outcome=str(resp.status_code), details={"key_id": key_id, "client_id": client_id})
            if self.telemetry is not None:
                try:
                    self.telemetry.record_latency("web_request_latency_ms", (time.time() - t0) * 1000.0, tags={"path": path, "method": method, "status": resp.status_code})
                except Exception:
                    pass
            return resp
        except Exception as e:
            self.audit_logger.log(trace_id=trace_id, severity="ERROR", event="web.exception", ip=ip, endpoint=path, outcome="error", details={"error": str(e)})
            if self.telemetry is not None:
                try:
                    self.telemetry.increment_counter("errors_total", 1, tags={"subsystem": "web", "severity": "ERROR"})
                    self.telemetry.record_latency("web_request_latency_ms", (time.time() - t0) * 1000.0, tags={"path": path, "method": method, "status": "error"})
                except Exception:
                    pass
            raise

