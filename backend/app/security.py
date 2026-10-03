"""Auth utilities: password hashing, JWT sessions, CSRF, current-user deps.

Sessions are stateless signed JWTs stored in an httpOnly cookie (no sessions
table, no Redis).  A double-submit CSRF token is issued alongside; the SPA
reads the non-httpOnly `lq_csrf` cookie and echoes it in `X-CSRF-Token`.
API-key auth (`Authorization: Bearer lqk_...`) is supported for /api/v1.
"""
from __future__ import annotations

import hashlib
import hmac
import re
import secrets
import time
from datetime import datetime, timedelta, timezone

import jwt
from fastapi import Depends, HTTPException, Request, Response, status
from passlib.hash import bcrypt as _bcrypt

from . import config, db

# ---------------------------------------------------------------------------
# Passwords — bcrypt cost 12, min length enforced at the schema layer too.
# Lazy digest trick: passlib pre-hashes with sha256 so bcrypt's 72-byte cap
# never silently truncates long passphrases.
# ---------------------------------------------------------------------------
_bcrypt_ctx = _bcrypt.using(rounds=config.BCRYPT_ROUNDS)


def hash_password(plain: str) -> str:
    return _bcrypt_ctx.hash(plain)


def verify_password(plain: str, hashed: str) -> bool:
    try:
        return _bcrypt_ctx.verify(plain, hashed)
    except ValueError:
        return False


PASSWORD_MIN_LEN = 8
_PASSWORD_STRENGTH = re.compile(r"^(?=.*[A-Za-z])(?=.*\d).{8,}$")


def check_password_policy(pw: str) -> None:
    if not _PASSWORD_STRENGTH.match(pw):
        raise HTTPException(422, "Password must be at least 8 characters and contain a letter and a digit.")


# ---------------------------------------------------------------------------
# JWT session cookies
# ---------------------------------------------------------------------------
def issue_session(response: Response, user: dict) -> None:
    """Set the httpOnly session cookie + readable CSRF twin."""
    now = int(time.time())
    payload = {
        "sub": str(user["id"]),
        "role": user["role"],
        "iat": now,
        "exp": now + config.SESSION_EXPIRE_HOURS * 3600,
        # Session id lets us invalidate all cookies for a user by bumping this.
        "sid": hashlib.sha256(f"{user['id']}|{now}|{secrets.token_hex(8)}".encode()).hexdigest()[:16],
    }
    token = jwt.encode(payload, config.SECRET_KEY, algorithm=config.JWT_ALG)
    csrf = secrets.token_urlsafe(24)
    max_age = config.SESSION_EXPIRE_HOURS * 3600
    response.set_cookie(config.COOKIE_SESSION, token, max_age=max_age,
                        httponly=True, samesite="lax", secure=_is_https(), path="/")
    response.set_cookie(config.COOKIE_CSRF, csrf, max_age=max_age,
                        httponly=False, samesite="lax", secure=_is_https(), path="/")


def clear_session(response: Response) -> None:
    response.delete_cookie(config.COOKIE_SESSION, path="/")
    response.delete_cookie(config.COOKIE_CSRF, path="/")


def _is_https() -> bool:
    return config.PUBLIC_BASE_URL.startswith("https://")


def decode_session(request: Request) -> dict | None:
    raw = request.cookies.get(config.COOKIE_SESSION)
    if not raw:
        return None
    try:
        return jwt.decode(raw, config.SECRET_KEY, algorithms=[config.JWT_ALG])
    except jwt.PyJWTError:
        return None


# ---------------------------------------------------------------------------
# CSRF — double-submit token verification on unsafe methods.
# SameSite=Lax already blocks cross-site form posts from other origins; the
# mirrored header adds defense-in-depth for same-site subdomain edge cases.
# ---------------------------------------------------------------------------
_UNSAFE = {"POST", "PUT", "PATCH", "DELETE"}


def verify_csrf(request: Request) -> None:
    if request.method not in _UNSAFE:
        return
    # API-key requests are not browser-based → CSRF does not apply.
    if request.headers.get("authorization", "").startswith("Bearer lqk_"):
        return
    cookie = request.cookies.get(config.COOKIE_CSRF, "")
    header = request.headers.get("x-csrf-token", "")
    if not cookie or not header or not hmac.compare_digest(cookie, header):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "CSRF token missing or invalid.")


# ---------------------------------------------------------------------------
# Current user dependencies
# ---------------------------------------------------------------------------
def _user_by_id(conn, uid: int) -> dict:
    user = db.q1(conn, "SELECT id,email,name,avatar_url,role,verified,banned FROM users WHERE id=?", (uid,))
    if not user:
        raise HTTPException(401, "Session refers to a deleted user.")
    if user["banned"]:
        raise HTTPException(403, "Account suspended.")
    return user


def get_current_user(request: Request, conn=Depends(db.get_db)) -> dict:
    claims = decode_session(request)
    if not claims:
        raise HTTPException(401, "Not authenticated.")
    return _user_by_id(conn, int(claims["sub"]))


def get_optional_user(request: Request, conn=Depends(db.get_db)) -> dict | None:
    claims = decode_session(request)
    if not claims:
        return None
    try:
        return _user_by_id(conn, int(claims["sub"]))
    except HTTPException:
        return None


def require_admin(user: dict = Depends(get_current_user)) -> dict:
    if user["role"] != "admin":
        raise HTTPException(403, "Admin privileges required.")
    return user


# ---------------------------------------------------------------------------
# API keys: raw key shown once, only sha256 stored.  Prefix keeps lookup O(1)
# via the unique hash index after candidate filtering by prefix.
# ---------------------------------------------------------------------------
API_KEY_PREFIX_LEN = 12  # "lqk_" + 8 visible chars


def generate_api_key() -> tuple[str, str]:
    raw = "lqk_" + secrets.token_urlsafe(32)
    return raw, hashlib.sha256(raw.encode()).hexdigest()


def authenticate_api_key(request: Request, conn) -> dict | None:
    auth = request.headers.get("authorization", "")
    if not auth.startswith("Bearer lqk_"):
        return None
    raw = auth[len("Bearer "):]
    key_hash = hashlib.sha256(raw.encode()).hexdigest()
    row = db.q1(conn, "SELECT user_id FROM api_keys WHERE key_hash=?", (key_hash,))
    if not row:
        raise HTTPException(401, "Invalid API key.")
    conn.execute("UPDATE api_keys SET last_used=datetime('now') WHERE key_hash=?", (key_hash,))
    return _user_by_id(conn, row["user_id"])


def user_from_request(request: Request, conn) -> dict | None:
    """Resolve identity from API key first, then session cookie."""
    u = authenticate_api_key(request, conn)
    if u:
        return u
    claims = decode_session(request)
    if not claims:
        return None
    try:
        return _user_by_id(conn, int(claims["sub"]))
    except HTTPException:
        return None


# ---------------------------------------------------------------------------
# Single-use tokens (email verification / password reset)
# ---------------------------------------------------------------------------
def create_token(conn, user_id: int, purpose: str, hours: int = 48) -> str:
    raw = secrets.token_urlsafe(32)
    th = hashlib.sha256(raw.encode()).hexdigest()
    exp = (datetime.now(timezone.utc) + timedelta(hours=hours)).isoformat()
    conn.execute("INSERT INTO tokens (user_id,purpose,token_hash,expires_at) VALUES (?,?,?,?)",
                 (user_id, purpose, th, exp))
    return raw


def consume_token(conn, purpose: str, raw: str) -> int:
    th = hashlib.sha256(raw.encode()).hexdigest()
    row = db.q1(conn, "SELECT * FROM tokens WHERE token_hash=? AND purpose=? AND used=0", (th, purpose))
    if not row:
        raise HTTPException(400, "Invalid or expired token.")
    if datetime.fromisoformat(row["expires_at"]) < datetime.now(timezone.utc):
        raise HTTPException(400, "Invalid or expired token.")
    conn.execute("UPDATE tokens SET used=1 WHERE id=?", (row["id"],))
    return row["user_id"]
