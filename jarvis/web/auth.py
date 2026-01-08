from __future__ import annotations

from typing import Callable, Optional

from fastapi import Header, HTTPException, Request


def build_api_key_auth(api_key: str, event_logger) -> Callable[..., object]:
    async def dep(request: Request, x_api_key: str = Header(default="")) -> None:
        trace_id = getattr(getattr(request, "state", None), "trace_id", "web")
        client_host = getattr(getattr(request, "client", None), "host", None)
        if not x_api_key:
            event_logger.log(trace_id, "web.auth.failed", {"reason": "missing", "client_host": client_host, "path": str(request.url.path)})
            raise HTTPException(status_code=401, detail="Missing API key.")
        if x_api_key != api_key:
            event_logger.log(trace_id, "web.auth.failed", {"reason": "invalid", "client_host": client_host, "path": str(request.url.path)})
            raise HTTPException(status_code=401, detail="Invalid API key.")
        event_logger.log(trace_id, "web.auth.ok", {"client_host": client_host, "path": str(request.url.path)})

    return dep


