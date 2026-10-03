"""Admin panel API: users, surveys, site settings, disk stats, backups."""
from __future__ import annotations

import time

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import FileResponse

from .. import config, db, security
from ..schemas import AdminSettingsIn

router = APIRouter(prefix="/admin", tags=["admin"])


# ---------------------------------------------------------------------------
# Users
# ---------------------------------------------------------------------------
@router.get("/users")
def list_users(page: int = Query(1, ge=1),
               limit: int = Query(db.config.PAGE_SIZE_DEFAULT, ge=1, le=db.config.PAGE_SIZE_MAX),
               q: str = Query("", max_length=100),
               admin=Depends(security.require_admin), conn=Depends(db.get_db)):
    where, params = "1=1", []
    if q:
        where += " AND (email LIKE ? OR name LIKE ?)"
        params += [f"%{q}%", f"%{q}%"]
    total = db.q1(conn, f"SELECT COUNT(*) c FROM users WHERE {where}", tuple(params))["c"]
    rows = db.q(conn,
        f"""SELECT id,email,name,role,verified,banned,created_at,
                   (SELECT COUNT(*) FROM surveys s WHERE s.owner_id=users.id) AS survey_count
            FROM users WHERE {where} ORDER BY created_at DESC LIMIT ? OFFSET ?""",
        tuple(params) + (limit, (page - 1) * limit))
    return {"items": rows, "total": total, "page": page, "limit": limit}


@router.post("/users/{user_id}/ban")
def ban_user(user_id: int, body: dict, request: Request,
             csrf=Depends(security.verify_csrf),
             admin=Depends(security.require_admin), conn=Depends(db.get_db)):
    banned = bool(body.get("banned", True))
    if user_id == admin["id"]:
        raise HTTPException(422, "You cannot ban yourself.")
    conn.execute("UPDATE users SET banned=? WHERE id=?", (int(banned), user_id))
    return {"ok": True}


@router.post("/users/{user_id}/role")
def set_role(user_id: int, body: dict, request: Request,
             csrf=Depends(security.verify_csrf),
             admin=Depends(security.require_admin), conn=Depends(db.get_db)):
    role = body.get("role")
    if role not in ("user", "admin"):
        raise HTTPException(422, "Role must be 'user' or 'admin'.")
    if user_id == admin["id"] and role != "admin":
        raise HTTPException(422, "You cannot demote yourself.")
    conn.execute("UPDATE users SET role=? WHERE id=?", (role, user_id))
    return {"ok": True}


@router.delete("/users/{user_id}")
def delete_user(user_id: int, request: Request,
                csrf=Depends(security.verify_csrf),
                admin=Depends(security.require_admin), conn=Depends(db.get_db)):
    if user_id == admin["id"]:
        raise HTTPException(422, "You cannot delete your own account here.")
    conn.execute("DELETE FROM users WHERE id=?", (user_id,))   # cascades via FKs
    return {"deleted": True}


# ---------------------------------------------------------------------------
# Surveys (global view)
# ---------------------------------------------------------------------------
@router.get("/surveys")
def all_surveys(page: int = Query(1, ge=1),
                limit: int = Query(db.config.PAGE_SIZE_DEFAULT, ge=1, le=db.config.PAGE_SIZE_MAX),
                q: str = Query("", max_length=100),
                admin=Depends(security.require_admin), conn=Depends(db.get_db)):
    where, params = "1=1", []
    if q:
        where += " AND (s.title LIKE ? OR s.slug LIKE ? OR u.email LIKE ?)"
        params += [f"%{q}%"] * 3
    total = db.q1(conn,
        f"SELECT COUNT(*) c FROM surveys s JOIN users u ON u.id=s.owner_id WHERE {where}",
        tuple(params))["c"]
    rows = db.q(conn,
        f"""SELECT s.id,s.slug,s.title,s.published,s.closed,s.created_at,s.updated_at,
                   u.email AS owner_email,
                   (SELECT COUNT(*) FROM responses r WHERE r.survey_id=s.id AND r.submitted_at IS NOT NULL) AS response_count
            FROM surveys s JOIN users u ON u.id=s.owner_id
            WHERE {where} ORDER BY s.updated_at DESC LIMIT ? OFFSET ?""",
        tuple(params) + (limit, (page - 1) * limit))
    return {"items": rows, "total": total, "page": page, "limit": limit}


@router.post("/surveys/{survey_id}/force-close")
def force_close(survey_id: int, request: Request,
                csrf=Depends(security.verify_csrf),
                admin=Depends(security.require_admin), conn=Depends(db.get_db)):
    conn.execute("UPDATE surveys SET closed=1 WHERE id=?", (survey_id,))
    return {"closed": True}


@router.delete("/surveys/{survey_id}")
def admin_delete_survey(survey_id: int, request: Request,
                        csrf=Depends(security.verify_csrf),
                        admin=Depends(security.require_admin), conn=Depends(db.get_db)):
    conn.execute("DELETE FROM surveys WHERE id=?", (survey_id,))
    return {"deleted": True}


# ---------------------------------------------------------------------------
# Site settings — stored in the `settings` key/value table.
# ---------------------------------------------------------------------------
_SETTING_KEYS = ("site_name", "registration_open", "require_email_verification",
                 "smtp_host", "smtp_port", "smtp_user", "smtp_pass", "smtp_from",
                 "session_hours", "max_upload_mb")


@router.get("/settings")
def get_settings(admin=Depends(security.require_admin), conn=Depends(db.get_db)):
    rows = db.q(conn, "SELECT key,value FROM settings")
    out = {r["key"]: r["value"] for r in rows}
    # Never expose the SMTP password through the API; UI shows a masked hint.
    if "smtp_pass" in out:
        out["smtp_pass_set"] = bool(out.pop("smtp_pass"))
    return {"settings": out}


@router.put("/settings")
def put_settings(body: AdminSettingsIn, request: Request,
                 csrf=Depends(security.verify_csrf),
                 admin=Depends(security.require_admin), conn=Depends(db.get_db)):
    data = body.model_dump()
    conn.execute("BEGIN")
    try:
        for k, v in data.items():
            if k == "smtp_pass" and v == "":
                continue                      # empty string keeps existing secret
            val = ("1" if v is True else "0" if v is False else str(v))
            conn.execute("INSERT INTO settings (key,value) VALUES (?,?) "
                         "ON CONFLICT(key) DO UPDATE SET value=excluded.value", (k, val))
        conn.execute("COMMIT")
    except Exception:
        conn.execute("ROLLBACK")
        raise
    return {"ok": True}


# ---------------------------------------------------------------------------
# Disk usage & SQLite backup download
# ---------------------------------------------------------------------------
@router.get("/stats")
def stats(admin=Depends(security.require_admin), conn=Depends(db.get_db)):
    counts = db.q1(conn,
        """SELECT (SELECT COUNT(*) FROM users) users,
                  (SELECT COUNT(*) FROM surveys) surveys,
                  (SELECT COUNT(*) FROM responses WHERE submitted_at IS NOT NULL) responses""")
    return {"counts": counts, "disk": db.disk_usage()}


@router.post("/backup")
def trigger_backup(request: Request,
                   csrf=Depends(security.verify_csrf),
                   admin=Depends(security.require_admin)):
    """Create an online-consistent .sqlite snapshot and stream it to the caller.

    The snapshot lives in data/backups/ and is also useful for cron-based
    rotation; we keep the newest 5 and prune older ones automatically so a
    small VPS never fills its disk from our own backups.
    """
    backup_dir = config.DATA_DIR / "backups"
    backup_dir.mkdir(parents=True, exist_ok=True)
    fname = f"lunaquest-{time.strftime('%Y%m%d-%H%M%S')}.sqlite"
    dest = db.backup_to(backup_dir / fname)
    # Prune old snapshots (keep 5 most recent).
    snaps = sorted(backup_dir.glob("lunaquest-*.sqlite"), key=lambda p: p.name, reverse=True)
    for old in snaps[5:]:
        old.unlink(missing_ok=True)
    return FileResponse(dest, media_type="application/octet-stream",
                        filename=fname, headers={"content-disposition":
                                                 f'attachment; filename="{fname}"'})
