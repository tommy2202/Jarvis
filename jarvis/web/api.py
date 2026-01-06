from __future__ import annotations

import uuid

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse

from typing import Callable, Optional
from jarvis.web.models import AdminUnlockRequest, AdminUnlockResponse, MessageRequest, MessageResponse


def _is_localhost(request: Request) -> bool:
    host = getattr(getattr(request, "client", None), "host", "") or ""
    return host in {"127.0.0.1", "::1", "localhost"}


def create_app(
    jarvis_app,
    security_manager,
    event_logger,
    logger,
    auth_dep: Optional[Callable[..., object]],
    allowed_origins: list[str] | None = None,
    enable_web_ui: bool = True,
    allow_remote_admin_unlock: bool = False,
    remote_control_enabled: bool = True,
) -> FastAPI:
    app = FastAPI(title="Jarvis Remote", version="0.1.0")

    if allowed_origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=allowed_origins,
            allow_credentials=False,
            allow_methods=["*"],
            allow_headers=["*"],
        )

    @app.middleware("http")
    async def log_requests(request: Request, call_next):
        # Every inbound web request gets a trace_id (even auth failures).
        request.state.trace_id = uuid.uuid4().hex
        trace_id = request.state.trace_id
        client_host = getattr(getattr(request, "client", None), "host", None)
        event_logger.log(trace_id, "web.request", {"path": str(request.url.path), "method": request.method, "client_host": client_host})
        return await call_next(request)

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

    def _require_auth():
        if auth_dep is None:
            raise HTTPException(status_code=503, detail="Web auth not configured (USB key + API key required).")
        return auth_dep

    @app.post("/v1/message", response_model=MessageResponse)
    async def post_message(req: MessageRequest, request: Request, _=Depends(_require_auth())):
        if not remote_control_enabled:
            raise HTTPException(status_code=503, detail="Remote control disabled (USB key required).")
        resp = jarvis_app.process_message(req.message, client=(req.client.model_dump() if req.client else {}))
        return MessageResponse(
            trace_id=resp.trace_id,
            reply=resp.reply,
            intent={"id": resp.intent_id, "source": resp.intent_source, "confidence": resp.confidence},
            requires_followup=resp.requires_followup,
            followup_question=resp.followup_question,
        )

    @app.post("/v1/admin/unlock", response_model=AdminUnlockResponse)
    async def admin_unlock(req: AdminUnlockRequest, request: Request, _=Depends(_require_auth())):
        if not remote_control_enabled:
            raise HTTPException(status_code=503, detail="Remote control disabled (USB key required).")
        if not allow_remote_admin_unlock and not _is_localhost(request):
            raise HTTPException(status_code=403, detail="Remote admin unlock disabled by policy.")
        # Never log passphrase; EventLogger redacts anyway, but we avoid logging body entirely.
        ok = security_manager.verify_and_unlock_admin(req.passphrase)
        msg = "Admin unlocked." if ok else "Invalid passphrase or USB key missing."
        return AdminUnlockResponse(ok=ok, message=msg)

    return app

