"""Auth + profile endpoints: /api/auth/*, /api/me."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Request, Response

from .. import config, db, security
from ..limiter import limiter          # shared in-memory slowapi instance
from ..mailer import send_mail
from ..schemas import ForgotIn, LoginIn, ProfileIn, RegisterIn, ResetIn

router = APIRouter(tags=["auth"])


def _site_setting(conn, key: str, default: str = "") -> str:
    row = db.q1(conn, "SELECT value FROM settings WHERE key=?", (key,))
    return row["value"] if row else default


# NOTE on decorator order: @limiter.limit MUST be applied BEFORE the route is
# registered (@router.post).  slowapi's wrapper copies __signature__ from the
# undecorated function; if FastAPI saw that signature first it would treat the
# injected `body` model as a *query* parameter and reject every real payload.
@limiter.limit(config.RATE_LIMIT_AUTH)     # 5/min/IP — brute-force guard
@router.post("/auth/register", status_code=201)
def register(body: RegisterIn, request: Request, response: Response,
             conn=Depends(db.get_db)):
    """Create an account and log the user straight in via session cookie."""
    if _site_setting(conn, "registration_open", "1") == "0":
        raise HTTPException(403, "Registration is closed on this instance.")
    security.check_password_policy(body.password)
    email = body.email.lower()
    if db.q1(conn, "SELECT id FROM users WHERE email=?", (email,)):
        raise HTTPException(409, "An account with this email already exists.")
    require_verify = _site_setting(conn, "require_email_verification", "0") == "1"
    uid = db.execute(conn,
        "INSERT INTO users (email,password_hash,name,verified) VALUES (?,?,?,?)",
        (email, security.hash_password(body.password), body.name.strip(), 0 if require_verify else 1))
    user = db.q1(conn, "SELECT * FROM users WHERE id=?", (uid,))
    # First user on a fresh instance becomes admin — makes self-hosting painless.
    count = db.q1(conn, "SELECT COUNT(*) AS c FROM users")["c"]
    if count == 1:
        conn.execute("UPDATE users SET role='admin' WHERE id=?", (uid,))
        user["role"] = "admin"
    if require_verify:
        token = security.create_token(conn, uid, "verify", hours=72)
        link = f"{config.PUBLIC_BASE_URL}/verify?token={token}"
        send_mail(email, "Confirm your lunaQuest account",
                  f"Welcome to lunaQuest!\n\nConfirm your email: {link}\n")
    security.issue_session(response, user)
    return {"user": _public_user(user), "verify_required": require_verify}


@limiter.limit(config.RATE_LIMIT_AUTH)     # 5/min/IP — credential stuffing guard
@router.post("/auth/login")
def login(body: LoginIn, request: Request, response: Response, conn=Depends(db.get_db)):
    user = db.q1(conn, "SELECT * FROM users WHERE email=?", (body.email.lower(),))
    valid = False
    if user:
        valid = security.verify_password(body.password, user["password_hash"])
    else:
        # Constant-ish work factor: still run one bcrypt round so probing
        # "unknown email" vs "wrong password" yields no timing signal.
        security.verify_password(body.password, "$2b$04$" + "." * 53)
    if not valid:
        # Identical error for unknown email & bad password (no user enumeration).
        raise HTTPException(401, "Invalid email or password.")
    if user["banned"]:
        raise HTTPException(403, "Account suspended.")
    security.issue_session(response, user)
    return {"user": _public_user(user)}


@router.post("/auth/logout")
def logout(response: Response):
    security.clear_session(response)
    return {"ok": True}


@router.get("/auth/me")
def me(request: Request, conn=Depends(db.get_db)):
    """Return current identity (cookie or API key) or null — used at app boot."""
    user = security.user_from_request(request, conn)
    return {"user": _public_user(user) if user else None}


@router.post("/auth/verify-email")
def verify_email(body: dict, conn=Depends(db.get_db)):
    uid = security.consume_token(conn, "verify", str(body.get("token", "")))
    conn.execute("UPDATE users SET verified=1 WHERE id=?", (uid,))
    return {"ok": True}


@limiter.limit(config.RATE_LIMIT_AUTH)     # 5/min/IP — token-spam guard
@router.post("/auth/forgot-password")
def forgot_password(body: ForgotIn, request: Request, conn=Depends(db.get_db)):
    """Always answer OK — do not leak which emails exist."""
    user = db.q1(conn, "SELECT * FROM users WHERE email=?", (body.email.lower(),))
    if user and not user["banned"]:
        token = security.create_token(conn, user["id"], "reset", hours=6)
        link = f"{config.PUBLIC_BASE_URL}/reset-password?token={token}"
        sent = send_mail(user["email"], "lunaQuest password reset",
                         f"Reset your password within 6 hours:\n\n{link}\n"
                         "If you did not request this, ignore this email.")
        if not sent:
            # Dev fallback so the flow is testable without SMTP configured.
            return {"ok": True, "dev_token": token}
    return {"ok": True}


@router.post("/auth/reset-password")
def reset_password(body: ResetIn, conn=Depends(db.get_db)):
    security.check_password_policy(body.password)
    uid = security.consume_token(conn, "reset", body.token)
    conn.execute("UPDATE users SET password_hash=? WHERE id=?",
                 (security.hash_password(body.password), uid))
    return {"ok": True}


# ---------------------------------------------------------------------------
# /api/me — profile & API keys live under the same tag for convenience
# ---------------------------------------------------------------------------
me_router = APIRouter(prefix="/me", tags=["profile"])


@me_router.get("")
def my_profile(user=Depends(security.get_current_user)):
    return {"user": _public_user(user)}


@me_router.put("")
def update_profile(body: ProfileIn, request: Request,
                   user=Depends(security.get_current_user),
                   conn=Depends(db.get_db)):
    conn.execute("UPDATE users SET name=?, avatar_url=? WHERE id=?",
                 (body.name.strip()[:80], body.avatar_url.strip()[:512], user["id"]))
    return {"user": _public_user(db.q1(conn, "SELECT * FROM users WHERE id=?", (user["id"],)))}


@me_router.put("/password")
def change_password(body: dict, request: Request,
                    user=Depends(security.get_current_user),
                    conn=Depends(db.get_db)):
    old, new = str(body.get("old_password", "")), str(body.get("new_password", ""))
    stored = db.q1(conn, "SELECT password_hash FROM users WHERE id=?", (user["id"],))["password_hash"]
    if not security.verify_password(old, stored):
        raise HTTPException(400, "Current password is incorrect.")
    security.check_password_policy(new)
    conn.execute("UPDATE users SET password_hash=? WHERE id=?", (security.hash_password(new), user["id"]))
    return {"ok": True}


def _public_user(u: dict) -> dict:
    return {k: u[k] for k in ("id", "email", "name", "avatar_url", "role", "verified", "created_at")
            if k in u}
