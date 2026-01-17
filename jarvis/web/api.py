from __future__ import annotations

import uuid

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse

from typing import Callable, Optional

from jarvis.web.models import (
    AdminUnlockRequest,
    AdminUnlockResponse,
    JobListResponse,
    JobStateResponse,
    JobSubmitRequest,
    JobSubmitResponse,
    MessageRequest,
    MessageResponse,
)
from jarvis.web.middleware import WebSecurityMiddleware
from jarvis.core.errors import JarvisError
from jarvis.core.error_reporter import ErrorReporter
from jarvis.core.errors import PermissionDeniedError
from jarvis.core.capabilities.models import RequestContext, RequestSource
from jarvis.core.policy.models import PolicyContext


def _is_localhost(request: Request) -> bool:
    host = getattr(getattr(request, "client", None), "host", "") or ""
    return host in {"127.0.0.1", "::1", "localhost"}


def create_app(
    jarvis_app,
    security_manager,
    event_logger,
    logger,
    auth_dep: Optional[Callable[..., object]],  # legacy, ignored by hardened middleware
    job_manager=None,
    runtime=None,
    secure_store=None,
    web_cfg: Optional[dict] = None,
    telemetry=None,
    draining_event=None,
    allowed_origins: list[str] | None = None,
    enable_web_ui: bool = True,
    allow_remote_admin_unlock: bool = False,
    remote_control_enabled: bool = True,
    lockdown_manager=None,
) -> FastAPI:
    app = FastAPI(title="Jarvis Remote", version="0.1.0")
    reporter = ErrorReporter()

    if allowed_origins:
        if any(o == "*" for o in allowed_origins):
            raise ValueError("Wildcard CORS origins are not allowed.")
        app.add_middleware(
            CORSMiddleware,
            allow_origins=allowed_origins,
            allow_credentials=False,
            allow_methods=["*"],
            allow_headers=["*"],
        )
    # Hardened security middleware (requires secure_store)
    if secure_store is None or web_cfg is None:
        raise ValueError("secure_store and web_cfg required for hardened web app.")
    from jarvis.core.security_events import SecurityAuditLogger

    app.middleware("http")(WebSecurityMiddleware(web_cfg=web_cfg, secure_store=secure_store, event_logger=event_logger, audit_logger=SecurityAuditLogger(), telemetry=telemetry))

    @app.exception_handler(JarvisError)
    async def jarvis_error_handler(request: Request, exc: JarvisError):
        trace_id = getattr(getattr(request, "state", None), "trace_id", "web")
        reporter.write_error(exc, trace_id=trace_id, subsystem="web", internal_exc=None)
        code = 500
        if exc.code in {"permission_denied", "admin_required"}:
            code = 403
        elif exc.code in {"validation_error"}:
            code = 400
        elif exc.code in {"rate_limited"}:
            code = 429
        elif exc.code in {"llm_unavailable"}:
            code = 503
        return JSONResponse(status_code=code, content={"detail": exc.user_message, "code": exc.code})

    @app.exception_handler(RequestValidationError)
    async def request_validation_handler(request: Request, exc: RequestValidationError):
        trace_id = getattr(getattr(request, "state", None), "trace_id", "web")
        reporter.write_error(JarvisError(code="validation_error", user_message="Invalid request.", context={"errors": exc.errors()}), trace_id=trace_id, subsystem="web", internal_exc=None)
        return JSONResponse(status_code=400, content={"detail": "Invalid request.", "code": "validation_error"})

    @app.get("/health")
    async def health():
        return {"status": "ok"}

    if enable_web_ui:
        @app.get("/", response_class=HTMLResponse)
        async def root():
            return """<!doctype html>
<html>
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1"/>
  <title>Jarvis Remote</title>
  <style>
    body{font-family:system-ui,Segoe UI,Arial;margin:24px;max-width:720px}
    input,button{font-size:16px;padding:10px}
    input{width:100%;margin:10px 0}
    pre{background:#111;color:#eee;padding:12px;overflow:auto}
  </style>
</head>
<body>
  <h3>Jarvis Remote</h3>
  <p>Enter your API key and a message.</p>
  <input id="key" placeholder="API key (X-API-Key)"/>
  <input id="msg" placeholder="Message (e.g. play Coldplay on Spotify)"/>
  <button onclick="send()">Send</button>
  <pre id="out"></pre>
  <script>
    async function send(){
      const key = document.getElementById('key').value;
      const message = document.getElementById('msg').value;
      const r = await fetch('/v1/message', {
        method:'POST',
        headers:{'Content-Type':'application/json','X-API-Key':key},
        body: JSON.stringify({message, client:{name:'web', id:'browser'}})
      });
      const txt = await r.text();
      document.getElementById('out').textContent = txt;
    }
  </script>
</body>
</html>"""

    @app.post("/v1/message", response_model=MessageResponse)
    async def post_message(req: MessageRequest, request: Request):
        if draining_event is not None and getattr(draining_event, "is_set", lambda: False)():
            raise HTTPException(status_code=503, detail="Shutting down")
        if not remote_control_enabled:
            raise HTTPException(status_code=503, detail="Remote control disabled (USB key required).")
        if runtime is not None:
            trace_id = runtime.submit_text(
                "web",
                req.message,
                client_meta=(req.client.model_dump() if req.client else {}),
                trace_id=getattr(getattr(request, "state", None), "trace_id", None),
            )
            out = runtime.wait_for_result(trace_id, timeout_seconds=20.0)
            if not out:
                raise HTTPException(status_code=504, detail="Timed out waiting for result.")
            intent = out.get("intent") or {"id": "unknown", "source": "system", "confidence": 0.0}
            return MessageResponse(
                trace_id=trace_id,
                reply=out.get("reply") or "",
                intent=intent,
                requires_followup=False,
                followup_question=None,
            )
        try:
            resp = jarvis_app.process_message(
                req.message,
                client=(req.client.model_dump() if req.client else {}),
                source="web",
                safe_mode=False,
                shutting_down=False,
                trace_id=getattr(getattr(request, "state", None), "trace_id", None),
            )
        except TypeError:
            resp = jarvis_app.process_message(req.message, client=(req.client.model_dump() if req.client else {}))
        return MessageResponse(
            trace_id=resp.trace_id,
            reply=resp.reply,
            intent={"id": resp.intent_id, "source": resp.intent_source, "confidence": resp.confidence},
            requires_followup=resp.requires_followup,
            followup_question=resp.followup_question,
        )

    @app.get("/v1/status")
    async def status(request: Request):
        if runtime is None:
            return {"state": "unknown"}
        return runtime.get_status()

    @app.get("/v1/health")
    async def telemetry_health(request: Request):
        tm = telemetry or getattr(runtime, "telemetry", None)
        if tm is None:
            return {"health": [], "status": "unavailable"}
        return {"health": tm.get_health()}

    @app.get("/v1/health/{subsystem}")
    async def telemetry_health_one(subsystem: str, request: Request):
        tm = telemetry or getattr(runtime, "telemetry", None)
        if tm is None:
            raise HTTPException(status_code=503, detail="Telemetry unavailable.")
        return {"health": tm.get_health(subsystem=subsystem)}

    @app.get("/v1/metrics")
    async def telemetry_metrics(request: Request):
        tm = telemetry or getattr(runtime, "telemetry", None)
        if tm is None:
            raise HTTPException(status_code=503, detail="Telemetry unavailable.")
        return tm.get_metrics_summary()

    @app.get("/v1/telemetry/snapshot")
    async def telemetry_snapshot(request: Request):
        tm = telemetry or getattr(runtime, "telemetry", None)
        if tm is None:
            raise HTTPException(status_code=503, detail="Telemetry unavailable.")
        return tm.get_snapshot()

    @app.get("/v1/capabilities")
    async def capabilities_list(request: Request):
        # Capabilities engine lives in app wiring via dispatcher
        eng = getattr(getattr(jarvis_app, "dispatcher", None), "capability_engine", None)
        if eng is None:
            raise HTTPException(status_code=503, detail="Capabilities unavailable.")
        return {"capabilities": eng.get_capabilities(), "recent": eng.audit.recent(50)}

    @app.get("/v1/capabilities/intents")
    async def capabilities_intents(request: Request):
        eng = getattr(getattr(jarvis_app, "dispatcher", None), "capability_engine", None)
        if eng is None:
            raise HTTPException(status_code=503, detail="Capabilities unavailable.")
        return {"intent_requirements": eng.get_intent_requirements()}

    @app.post("/v1/capabilities/eval")
    async def capabilities_eval(request: Request):
        eng = getattr(getattr(jarvis_app, "dispatcher", None), "capability_engine", None)
        if eng is None:
            raise HTTPException(status_code=503, detail="Capabilities unavailable.")
        body = await request.json()
        intent_id = str(body.get("intent_id") or "")
        simulate = bool(body.get("simulate", False))
        trace_id = getattr(getattr(request, "state", None), "trace_id", "web")

        admin_claim = bool("admin" in (getattr(getattr(request, "state", None), "scopes", []) or []))
        is_admin_actual = False
        if security_manager is not None:
            try:
                is_admin_actual = bool(security_manager.is_admin()) or bool(admin_claim)
            except Exception:
                is_admin_actual = False

        safe_mode_actual = True
        shutting_down_actual = True
        if runtime is not None:
            try:
                safe_mode_actual = bool(getattr(runtime, "safe_mode", False))
            except Exception:
                safe_mode_actual = True
            try:
                shutting_down_actual = bool(getattr(runtime, "_shutdown_in_progress", False))
            except Exception:
                shutting_down_actual = True
        if draining_event is not None and getattr(draining_event, "is_set", lambda: False)():
            shutting_down_actual = True

        simulated = bool(simulate and is_admin_actual)
        if simulated:
            is_admin = bool(body.get("is_admin", is_admin_actual))
            safe_mode = bool(body.get("safe_mode", safe_mode_actual))
            shutting_down = bool(body.get("shutting_down", shutting_down_actual))
        else:
            is_admin = bool(is_admin_actual)
            safe_mode = bool(safe_mode_actual)
            shutting_down = bool(shutting_down_actual)
        ctx = RequestContext(
            trace_id=trace_id,
            source=RequestSource("web"),
            is_admin=is_admin,
            safe_mode=safe_mode,
            shutting_down=shutting_down,
            subsystem_health={"breakers": getattr(getattr(runtime, "breakers", None), "status", lambda: {})()},
            intent_id=intent_id,
            secure_store_mode=(secure_store.status().mode.value if secure_store is not None else None),
        )
        out = eng.evaluate(ctx).model_dump()
        out["simulated"] = bool(simulated)
        return out

    @app.get("/v1/llm/status")
    async def llm_status(request: Request):
        if runtime is None or getattr(runtime, "llm_lifecycle", None) is None:
            return {"enabled": False}
        return runtime.llm_lifecycle.get_status()

    @app.get("/v1/secure/status")
    async def secure_status(request: Request):
        # Public status only; no secrets.
        if secure_store is None:
            return {"mode": "unavailable"}
        try:
            return secure_store.export_public_status()
        except Exception:
            return {"mode": "unavailable"}

    @app.get("/v1/policy/status")
    async def policy_status(request: Request):
        eng = getattr(getattr(jarvis_app, "dispatcher", None), "capability_engine", None)
        pe = getattr(eng, "policy_engine", None) if eng is not None else None
        if pe is None:
            return {"enabled": False}
        return pe.status()

    @app.get("/v1/policy/rules")
    async def policy_rules(request: Request):
        eng = getattr(getattr(jarvis_app, "dispatcher", None), "capability_engine", None)
        pe = getattr(eng, "policy_engine", None) if eng is not None else None
        if pe is None:
            raise HTTPException(status_code=503, detail="Policy unavailable.")
        return {"rules": pe.rules()}

    @app.post("/v1/policy/eval")
    async def policy_eval(request: Request):
        eng = getattr(getattr(jarvis_app, "dispatcher", None), "capability_engine", None)
        pe = getattr(eng, "policy_engine", None) if eng is not None else None
        if pe is None:
            raise HTTPException(status_code=503, detail="Policy unavailable.")
        body = await request.json()
        intent_id = str(body.get("intent_id") or "")
        simulate = bool(body.get("simulate", False))
        trace_id = getattr(getattr(request, "state", None), "trace_id", "web")

        admin_claim = bool("admin" in (getattr(getattr(request, "state", None), "scopes", []) or []))
        is_admin_actual = False
        if security_manager is not None:
            try:
                is_admin_actual = bool(security_manager.is_admin()) or bool(admin_claim)
            except Exception:
                is_admin_actual = False

        safe_mode_actual = True
        shutting_down_actual = True
        if runtime is not None:
            try:
                safe_mode_actual = bool(getattr(runtime, "safe_mode", False))
            except Exception:
                safe_mode_actual = True
            try:
                shutting_down_actual = bool(getattr(runtime, "_shutdown_in_progress", False))
            except Exception:
                shutting_down_actual = True
        if draining_event is not None and getattr(draining_event, "is_set", lambda: False)():
            shutting_down_actual = True

        simulated = bool(simulate and is_admin_actual)
        if simulated:
            is_admin = bool(body.get("is_admin", is_admin_actual))
            safe_mode = bool(body.get("safe_mode", safe_mode_actual))
            shutting_down = bool(body.get("shutting_down", shutting_down_actual))
        else:
            is_admin = bool(is_admin_actual)
            safe_mode = bool(safe_mode_actual)
            shutting_down = bool(shutting_down_actual)
        req_caps = eng.get_intent_requirements().get(intent_id) if eng is not None else []
        pctx = PolicyContext(
            trace_id=trace_id,
            intent_id=intent_id,
            source="web",
            is_admin=is_admin,
            safe_mode=safe_mode,
            shutting_down=shutting_down,
            required_capabilities=list(req_caps or []),
        )
        out = pe.evaluate(pctx).model_dump()
        out["simulated"] = bool(simulated)
        return out

    # ---- Modules API (authenticated; admin required for enable/disable) ----
    @app.get("/v1/modules")
    async def modules_list(request: Request):
        if runtime is None:
            raise HTTPException(status_code=503, detail="Runtime unavailable.")
        return runtime.get_modules_status()

    @app.post("/v1/modules/scan")
    async def modules_scan(request: Request):
        if draining_event is not None and getattr(draining_event, "is_set", lambda: False)():
            raise HTTPException(status_code=503, detail="Shutting down")
        if runtime is None:
            raise HTTPException(status_code=503, detail="Runtime unavailable.")
        return runtime.modules_scan()

    @app.post("/v1/modules/enable")
    async def modules_enable(request: Request):
        if runtime is None:
            raise HTTPException(status_code=503, detail="Runtime unavailable.")
        body = await request.json()
        mid = str(body.get("module_id") or "")
        if not mid:
            raise HTTPException(status_code=400, detail="module_id required")
        try:
            ok = runtime.modules_enable(mid)
        except PermissionDeniedError:
            raise HTTPException(status_code=403, detail="Admin required.")
        return {"ok": bool(ok)}

    @app.post("/v1/modules/disable")
    async def modules_disable(request: Request):
        if runtime is None:
            raise HTTPException(status_code=503, detail="Runtime unavailable.")
        body = await request.json()
        mid = str(body.get("module_id") or "")
        if not mid:
            raise HTTPException(status_code=400, detail="module_id required")
        try:
            ok = runtime.modules_disable(mid)
        except PermissionDeniedError:
            raise HTTPException(status_code=403, detail="Admin required.")
        return {"ok": bool(ok)}

    # ---- Privacy / DSAR API (authenticated) ----
    @app.post("/v1/privacy/dsar")
    async def privacy_dsar_create(request: Request):
        if runtime is None:
            raise HTTPException(status_code=503, detail="Runtime unavailable.")
        eng = getattr(runtime, "dsar_engine", None)
        if eng is None:
            raise HTTPException(status_code=503, detail="DSAR unavailable.")
        body = await request.json()
        req_type = str(body.get("type") or body.get("request_type") or "export")
        payload = body.get("payload") if isinstance(body.get("payload"), dict) else {}
        trace_id = getattr(getattr(request, "state", None), "trace_id", "web")
        rid = eng.request(user_id="default", request_type=req_type, payload=payload, trace_id=str(trace_id))
        return {"request_id": rid, "type": req_type}

    @app.get("/v1/privacy/dsar/{request_id}")
    async def privacy_dsar_get(request_id: str, request: Request):
        if runtime is None:
            raise HTTPException(status_code=503, detail="Runtime unavailable.")
        eng = getattr(runtime, "dsar_engine", None)
        if eng is None:
            raise HTTPException(status_code=503, detail="DSAR unavailable.")
        req = eng.get(str(request_id))
        if req is None:
            raise HTTPException(status_code=404, detail="Not found.")
        return req.model_dump()

    @app.get("/v1/audit")
    async def audit_list(
        request: Request,
        since: float | None = None,
        until: float | None = None,
        category: str | None = None,
        outcome: str | None = None,
        actor_source: str | None = None,
        limit: int = 200,
        offset: int = 0,
    ):
        if runtime is None or getattr(runtime, "audit_timeline", None) is None:
            raise HTTPException(status_code=503, detail="Audit timeline unavailable.")
        rows = runtime.audit_timeline.list_events(
            since=since,
            until=until,
            category=category,
            outcome=outcome,
            actor_source=actor_source,
            limit=limit,
            offset=offset,
        )
        return {"events": [r.model_dump() for r in rows], "integrity_broken": bool(runtime.audit_timeline.integrity_broken())}

    @app.get("/v1/audit/integrity")
    async def audit_integrity(request: Request):
        if runtime is None or getattr(runtime, "audit_timeline", None) is None:
            raise HTTPException(status_code=503, detail="Audit timeline unavailable.")
        return runtime.audit_timeline.verify_integrity(limit_last_n=2000).model_dump()

    @app.get("/v1/audit/{audit_id}")
    async def audit_get(audit_id: str, request: Request):
        if runtime is None or getattr(runtime, "audit_timeline", None) is None:
            raise HTTPException(status_code=503, detail="Audit timeline unavailable.")
        ev = runtime.audit_timeline.get_event(audit_id)
        if ev is None:
            raise HTTPException(status_code=404, detail="Not found.")
        return ev.model_dump()

    @app.post("/v1/audit/purge")
    async def audit_purge(request: Request):
        if runtime is None or getattr(runtime, "audit_timeline", None) is None:
            raise HTTPException(status_code=503, detail="Audit timeline unavailable.")
        # Admin scope is enforced by middleware; additionally require admin session if available.
        if security_manager is not None and not bool(security_manager.is_admin()):
            raise PermissionDeniedError("Admin required.")
        return runtime.audit_timeline.purge_and_compact()

    @app.post("/v1/admin/unlock", response_model=AdminUnlockResponse)
    async def admin_unlock(req: AdminUnlockRequest, request: Request):
        if draining_event is not None and getattr(draining_event, "is_set", lambda: False)():
            raise HTTPException(status_code=503, detail="Shutting down")
        if not remote_control_enabled:
            raise HTTPException(status_code=503, detail="Remote control disabled (USB key required).")
        # Extra hardening:
        # - disabled by default (config)
        # - only allow from configured IP allowlist
        web_admin = (web_cfg.get("admin") or {}) if isinstance(web_cfg, dict) else {}
        allowed_admin_ips = set(web_admin.get("allowed_admin_ips") or ["127.0.0.1"])
        client_ip = getattr(getattr(request, "client", None), "host", None)
        allow_remote_unlock = bool(web_admin.get("allow_remote_unlock", False))
        if not allow_remote_unlock and not _is_localhost(request):
            raise PermissionDeniedError("Remote admin unlock disabled by policy.")
        if client_ip not in allowed_admin_ips and not _is_localhost(request):
            raise PermissionDeniedError("Admin unlock not allowed from this IP.")
        # Never log passphrase; EventLogger redacts anyway, but we avoid logging body entirely.
        ok = security_manager.verify_and_unlock_admin(req.passphrase)
        if lockdown_manager is not None:
            try:
                trace_id = getattr(getattr(request, "state", None), "trace_id", None)
                if ok:
                    lockdown_manager.record_admin_success()
                else:
                    lockdown_manager.record_admin_failure(trace_id=trace_id, source="web", details={"client_ip": client_ip})
            except Exception:
                pass
        msg = "Admin unlocked." if ok else "Invalid passphrase or USB key missing."
        return AdminUnlockResponse(ok=ok, message=msg)

    # Jobs API (authenticated; allowlist enforced by JobManager)
    if job_manager is not None:
        @app.post("/v1/jobs", response_model=JobSubmitResponse)
        async def submit_job(req: JobSubmitRequest, request: Request):
            if draining_event is not None and getattr(draining_event, "is_set", lambda: False)():
                raise HTTPException(status_code=503, detail="Shutting down")
            if not remote_control_enabled:
                raise HTTPException(status_code=503, detail="Remote control disabled (USB key required).")
            try:
                dispatcher = getattr(jarvis_app, "dispatcher", None)
                if dispatcher is None:
                    raise HTTPException(status_code=503, detail="Dispatcher unavailable.")
                trace_id = getattr(getattr(request, "state", None), "trace_id", "web")
                client_id = getattr(getattr(request, "client", None), "host", None)
                ctx = {
                    "source": "web",
                    "client": {"name": "web", "id": client_id},
                    "safe_mode": bool(getattr(runtime, "safe_mode", False)) if runtime is not None else False,
                    "shutting_down": bool(draining_event.is_set()) if draining_event is not None else False,
                }
                res = dispatcher.submit_job(
                    trace_id,
                    req.kind,
                    req.args,
                    ctx,
                    priority=req.priority,
                    max_runtime_seconds=req.max_runtime_seconds,
                )
            except ValueError as e:
                raise HTTPException(status_code=400, detail=str(e)) from e
            if not res.ok:
                code = 400 if res.denied_reason == "job_submit_invalid" else 403
                raise HTTPException(status_code=code, detail=res.reply)
            return JobSubmitResponse(job_id=str(res.job_id))

        @app.get("/v1/jobs", response_model=JobListResponse)
        async def list_jobs(request: Request):
            jobs = [j.model_dump() for j in job_manager.list_jobs()]
            return JobListResponse(jobs=jobs)

        @app.get("/v1/jobs/{job_id}", response_model=JobStateResponse)
        async def get_job(job_id: str, request: Request):
            try:
                job = job_manager.get_job(job_id)
            except KeyError as e:
                raise HTTPException(status_code=404, detail="Job not found.") from e
            return JobStateResponse(job=job.model_dump())

        @app.post("/v1/jobs/{job_id}/cancel")
        async def cancel_job(job_id: str, request: Request):
            if draining_event is not None and getattr(draining_event, "is_set", lambda: False)():
                raise HTTPException(status_code=503, detail="Shutting down")
            ok = job_manager.cancel_job(job_id)
            return {"ok": ok}

    return app

