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
    allowed_origins: list[str] | None = None,
    enable_web_ui: bool = True,
    allow_remote_admin_unlock: bool = False,
    remote_control_enabled: bool = True,
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

    app.middleware("http")(WebSecurityMiddleware(web_cfg=web_cfg, secure_store=secure_store, event_logger=event_logger, audit_logger=SecurityAuditLogger()))

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
        if not remote_control_enabled:
            raise HTTPException(status_code=503, detail="Remote control disabled (USB key required).")
        if runtime is not None:
            trace_id = runtime.submit_text("web", req.message, client_meta=(req.client.model_dump() if req.client else {}))
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

    @app.post("/v1/admin/unlock", response_model=AdminUnlockResponse)
    async def admin_unlock(req: AdminUnlockRequest, request: Request):
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
        msg = "Admin unlocked." if ok else "Invalid passphrase or USB key missing."
        return AdminUnlockResponse(ok=ok, message=msg)

    # Jobs API (authenticated; allowlist enforced by JobManager)
    if job_manager is not None:
        @app.post("/v1/jobs", response_model=JobSubmitResponse)
        async def submit_job(req: JobSubmitRequest, request: Request):
            if not remote_control_enabled:
                raise HTTPException(status_code=503, detail="Remote control disabled (USB key required).")
            try:
                job_id = job_manager.submit_job(
                    req.kind,
                    req.args,
                    requested_by={"source": "web", "client_id": getattr(getattr(request, "client", None), "host", None)},
                    priority=req.priority,
                    max_runtime_seconds=req.max_runtime_seconds,
                )
            except ValueError as e:
                raise HTTPException(status_code=400, detail=str(e)) from e
            return JobSubmitResponse(job_id=job_id)

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
            ok = job_manager.cancel_job(job_id)
            return {"ok": ok}

    return app

