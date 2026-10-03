"""Application configuration.

All settings come from environment variables (12-factor style) with safe
defaults so the app boots on a bare VPS with zero configuration.  Nothing is
cached in memory beyond these scalars — keeping idle RAM well under 150 MB.
"""
from __future__ import annotations

import os
import secrets
from pathlib import Path

# ---------------------------------------------------------------------------
# Paths — data lives outside the code tree; uploads are stored OUTSIDE any
# web-served directory and are only reachable through an authenticated route.
# ---------------------------------------------------------------------------
DATA_DIR = Path(os.environ.get("LUNAQ_DATA_DIR", "/workspace/data"))
UPLOAD_DIR = DATA_DIR / "uploads"          # never served statically
DB_PATH = Path(os.environ.get("LUNAQ_DB", str(DATA_DIR / "lunaquest.sqlite3")))
MIGRATIONS_DIR = Path(__file__).resolve().parent.parent / "migrations"
FRONTEND_DIST = Path(os.environ.get("LUNAQ_FRONTEND_DIST",
                                    str(Path(__file__).resolve().parent.parent.parent / "frontend" / "dist")))

# ---------------------------------------------------------------------------
# Security
# ---------------------------------------------------------------------------
# SECRET_KEY signs JWTs and CSRF tokens.  If unset we generate one at boot and
# persist it next to the DB so sessions survive restarts on small boxes.
def _load_secret() -> str:
    env = os.environ.get("LUNAQ_SECRET_KEY")
    if env:
        return env
    secret_file = DATA_DIR / ".secret_key"
    if secret_file.exists():
        return secret_file.read_text().strip()
    generated = secrets.token_urlsafe(48)
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    secret_file.write_text(generated)
    return generated

SECRET_KEY = _load_secret()
JWT_ALG = "HS256"
SESSION_EXPIRE_HOURS = int(os.environ.get("LUNAQ_SESSION_HOURS", "72"))

BCRYPT_ROUNDS = int(os.environ.get("LUNAQ_BCRYPT_ROUNDS", "12"))   # M3/security: cost 12

# Upload limits (streamed to disk — never buffered fully in RAM).
MAX_UPLOAD_MB = int(os.environ.get("LUNAQ_MAX_UPLOAD_MB", "10"))
MAX_UPLOAD_BYTES = MAX_UPLOAD_MB * 1024 * 1024

# Allowed upload MIME types -> extensions (validated server-side, streamed).
ALLOWED_UPLOAD_TYPES = {
    "image/png": ".png", "image/jpeg": ".jpg", "image/webp": ".webp",
    "image/gif": ".gif", "application/pdf": ".pdf",
    "text/plain": ".txt", "text/csv": ".csv",
    "application/zip": ".zip",
}

# Pagination policy (memory rule: paginate everything, max 100).
PAGE_SIZE_DEFAULT = 25
PAGE_SIZE_MAX = 100

# Rate limiting (slowapi, in-memory — fine for a single worker).
RATE_LIMIT_AUTH = os.environ.get("LUNAQ_RATE_AUTH", "5/minute")
RATE_LIMIT_WRITE = os.environ.get("LUNAQ_RATE_WRITE", "60/minute")
RATE_LIMIT_TAKE = os.environ.get("LUNAQ_RATE_TAKE", "30/minute")

# ---------------------------------------------------------------------------
# SMTP (optional — password reset & owner notifications).  When unconfigured
# the app degrades gracefully: reset tokens are logged instead of emailed.
# ---------------------------------------------------------------------------
SMTP_HOST = os.environ.get("LUNAQ_SMTP_HOST", "")
SMTP_PORT = int(os.environ.get("LUNAQ_SMTP_PORT", "587"))
SMTP_USER = os.environ.get("LUNAQ_SMTP_USER", "")
SMTP_PASS = os.environ.get("LUNAQ_SMTP_PASS", "")
SMTP_FROM = os.environ.get("LUNAQ_SMTP_FROM", SMTP_USER or "no-reply@lunaquest.local")
SMTP_TLS = os.environ.get("LUNAQ_SMTP_TLS", "1") == "1"

PUBLIC_BASE_URL = os.environ.get("LUNAQ_PUBLIC_URL", "http://localhost:8000")

# Set to 1 ONLY when a hardened reverse proxy (Caddy/Nginx) rewrites
# X-Forwarded-For; controls whether public endpoints derive client IPs
# from that header (see routers/public.py dedupe note).
TRUST_PROXY = os.environ.get("LUNAQ_TRUST_PROXY", "0") == "1"

# Cookie names
COOKIE_SESSION = "lq_session"     # httpOnly JWT session cookie
COOKIE_CSRF = "lq_csrf"           # readable by JS, mirrored in X-CSRF-Token header
