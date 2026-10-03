"""Shared slowapi rate limiter (in-memory — fine for a single uvicorn worker).

Kept in its own module so routers can decorate endpoints with
@limiter.limit(...) without a circular import of app.main.  Trusts the first
hop of X-Forwarded-For when running behind Caddy/Nginx so per-IP limits keep
working in a reverse-proxy deployment.
"""
from __future__ import annotations

from fastapi import Request
from slowapi import Limiter


def _client_ip(request: Request) -> str:
    xff = request.headers.get("x-forwarded-for", "")
    if xff:
        return xff.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


limiter = Limiter(key_func=_client_ip, default_limits=[],
                  headers_enabled=True, storage_uri="memory://")
