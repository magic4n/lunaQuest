"""lunaQuest — FastAPI application entry point.

Run (production):
    uvicorn app.main:app --host 127.0.0.1 --port 8000 --workers 1

Design goals baked in:
  * single worker + SQLite WAL → idle RAM < 150 MB, peak < 500 MB
  * orjson response class everywhere (fast + low allocation)
  * slowapi in-memory rate limiting on auth & write endpoints
  * CSRF double-submit enforcement as an HTTP middleware for /api mutations
  * serves the built React SPA from frontend/dist with history fallback
"""
from __future__ import annotations

import logging
import os
from contextlib import asynccontextmanager

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")

from fastapi import Depends, FastAPI, Request            # noqa: E402
from fastapi.middleware.cors import CORSMiddleware       # noqa: E402
from fastapi.responses import ORJSONResponse, FileResponse  # noqa: E402
from fastapi.staticfiles import StaticFiles              # noqa: E402
from slowapi import Limiter, _rate_limit_exceeded_handler  # noqa: E402
from slowapi.errors import RateLimitExceeded             # noqa: E402
from slowapi.util import get_remote_address              # noqa: E402

from . import config, db, security                        # noqa: E402
from .limiter import limiter                              # noqa: E402
from .routers import admin as r_admin                     # noqa: E402
from .routers import auth as r_auth                       # noqa: E402
from .routers import misc as r_misc                       # noqa: E402
from .routers import public as r_public                   # noqa: E402
from .routers import responses as r_responses             # noqa: E402
from .routers import surveys as r_surveys                 # noqa: E402


@asynccontextmanager
async def lifespan(app: FastAPI):
    db.migrate()                                    # idempotent, runs once at boot
    yield


app = FastAPI(
    title="lunaQuest API",
    version="1.0.0",
    description="Self-hosted survey platform. AGPL-3.0.",
    default_response_class=ORJSONResponse,
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url=None,
)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# CORS: same-origin deployment is the norm (SPA served by this app or by
# Caddy on the same host).  Only enable explicit origins if LUNAQ_CORS is set.
if origins := os.environ.get("LUNAQ_CORS_ORIGINS", ""):
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[o.strip() for o in origins.split(",") if o.strip()],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )


# Endpoints that must be reachable BEFORE a session/CSRF cookie exists.
# SameSite=Lax + the double-submit middleware below still protect every other
# mutation; these are credential-entry points with no prior state to forge.
_CSRF_EXEMPT_PATHS = {"/api/auth/register", "/api/auth/login",
                      "/api/auth/forgot-password", "/api/auth/reset-password"}


@app.middleware("http")
async def csrf_middleware(request: Request, call_next):
    """Enforce double-submit CSRF on every cookie-authenticated mutation.

    Public survey-taking requests (no session cookie, no API key) are exempt:
    there is no authenticated state for an attacker to ride on.  Everything
    else under /api with an unsafe method must echo the `lq_csrf` cookie in
    the `X-CSRF-Token` header.
    """
    path = request.url.path
    has_session = bool(request.cookies.get(config.COOKIE_SESSION))
    has_api_key = request.headers.get("authorization", "").startswith("Bearer lqk_")
    is_exempt = (path in _CSRF_EXEMPT_PATHS
                 or (path.startswith("/api/public/") and not has_session and not has_api_key))
    if path.startswith("/api") and request.method in ("POST", "PUT", "PATCH", "DELETE") \
            and not is_exempt and (has_session or has_api_key):
        try:
            security.verify_csrf(request)
        except Exception as exc:  # HTTPException → JSON error response
            from fastapi.responses import JSONResponse
            status_code = getattr(exc, "status_code", 403)
            return JSONResponse({"detail": getattr(exc, "detail", "CSRF check failed.")},
                                status_code=status_code)
    response = await call_next(request)
    response.headers.setdefault("x-content-type-options", "nosniff")
    response.headers.setdefault("referrer-policy", "same-origin")
    return response


# ---------------------------------------------------------------------------
# Rate limiting — slowapi decorator style.  NOTE: `Depends(limiter.limit(...))`
# must never be used: FastAPI would treat the wrapped limiter function itself
# as a required query parameter and break every route in the router.  Instead
# each limited endpoint carries @limiter.limit("N/minute") inside its router
# module (auth: 5/min, survey writes: 60/min, public taking: 30/min).
# ---------------------------------------------------------------------------
app.state.limiter = limiter

# ---------------------------------------------------------------------------
# Routers — all under /api.  static_router first so /summary & /export beat
# /{response_id}.  Auth endpoints carry tight rate limits (5/min/IP) applied
# via @limiter.limit decorators registered on those routes.
# ---------------------------------------------------------------------------
app.include_router(r_auth.router, prefix="/api")
app.include_router(r_auth.me_router, prefix="/api")
app.include_router(r_misc.site_router, prefix="/api")
app.include_router(r_misc.templates_router, prefix="/api")
app.include_router(r_misc.router, prefix="/api")
app.include_router(r_surveys.router, prefix="/api")
app.include_router(r_responses.static_router, prefix="/api")
app.include_router(r_responses.router, prefix="/api")
app.include_router(r_public.router, prefix="/api")
app.include_router(r_public.files_router, prefix="/api")
app.include_router(r_admin.router, prefix="/api")

# ---------------------------------------------------------------------------
# Static SPA (built frontend).  Unknown non-/api paths fall back to index.html
# so client-side routing works; assets are immutable-cached by Vite hashing.
# ---------------------------------------------------------------------------
_dist = config.FRONTEND_DIST
if _dist.is_dir():
    app.mount("/assets", StaticFiles(directory=_dist / "assets"), name="spa-assets")

    @app.get("/{full_path:path}", include_in_schema=False)
    async def spa_fallback(full_path: str):
        candidate = (_dist / full_path).resolve()
        if full_path and str(candidate).startswith(str(_dist.resolve())) and candidate.is_file():
            return FileResponse(candidate)
        return FileResponse(_dist / "index.html")
else:
    @app.get("/", include_in_schema=False)
    async def root_hint():
        return {"app": "lunaQuest API", "docs": "/docs",
                "hint": "Build the frontend (npm run build in /frontend) to serve the SPA."}
