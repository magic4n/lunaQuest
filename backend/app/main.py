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
from .routers import admin as r_admin                     # noqa: E402
from .routers import auth as r_auth                       # noqa: E402
from .routers import misc as r_misc                       # noqa: E402
from .routers import public as r_public                   # noqa: E402
from .routers import responses as r_responses             # noqa: E402
from .routers import surveys as r_surveys                 # noqa: E402


# Trust the first hop of X-Forwarded-For when running behind Caddy/Nginx so
# per-IP rate limits keep working in a reverse-proxy deployment.
def _client_ip(request: Request) -> str:
    xff = request.headers.get("x-forwarded-for", "")
    if xff:
        return xff.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


limiter = Limiter(key_func=_client_ip, default_limits=[],
                  headers_enabled=True, storage_uri="memory://")


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


@app.middleware("http")
async def csrf_middleware(request: Request, call_next):
    """Enforce double-submit CSRF on every cookie-authenticated mutation."""
    path = request.url.path
    is_public_take = (path.startswith("/api/public/")
                      and not request.headers.get("authorization", "").startswith("Bearer lqk_")
                      and not request.cookies.get(config.COOKIE_SESSION))
    if path.startswith("/api") and request.method in ("POST", "PUT", "PATCH", "DELETE") and not is_public_take:
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
# Routers — all under /api.  static_router first so /summary & /export beat
# /{response_id}.  Auth endpoints carry tight rate limits (5/min/IP).
# ---------------------------------------------------------------------------
app.include_router(r_auth.router, prefix="/api",
                   dependencies=[Depends(limiter.limit(config.RATE_LIMIT_AUTH))])
app.include_router(r_auth.me_router, prefix="/api")
app.include_router(r_misc.site_router, prefix="/api")
app.include_router(r_misc.templates_router, prefix="/api")
app.include_router(r_misc.router, prefix="/api")
app.include_router(r_surveys.router, prefix="/api",
                   dependencies=[Depends(limiter.limit(config.RATE_LIMIT_WRITE))])
app.include_router(r_responses.static_router, prefix="/api")
app.include_router(r_responses.router, prefix="/api")
app.include_router(r_public.router, prefix="/api",
                   dependencies=[Depends(limiter.limit(config.RATE_LIMIT_TAKE))])
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
