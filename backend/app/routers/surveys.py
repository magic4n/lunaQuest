"""Survey CRUD, publish/close, duplication, sharing and the public take view.

All list endpoints are paginated (default 25 / max 100).  Question writes use
a replace-all strategy from the builder — one transaction, few round-trips.
"""
from __future__ import annotations

import json
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Request

from .. import db, security, surveys as S
from ..schemas import ShareIn, SurveyIn

router = APIRouter(prefix="/surveys", tags=["surveys"])


# ---------------------------------------------------------------------------
# Serialization helpers
# ---------------------------------------------------------------------------
def _decode_survey(row: dict) -> dict:
    row["settings"] = json.loads(row.pop("settings_json") or "{}")
    row["theme"] = json.loads(row.pop("theme_json") or "{}")
    row["quiz_mode"] = bool(row["quiz_mode"])
    row["published"] = bool(row["published"])
    row["closed"] = bool(row["closed"])
    return row


def _decode_question(row: dict, shuffle: bool = False) -> dict:
    cfg = json.loads(row.pop("config_json") or "{}")
    logic = json.loads(row.pop("logic_json") or "[]")
    correct = json.loads(row.pop("correct_json") or "null")
    if shuffle:
        cfg = S.shuffle_choices(cfg)
    row["config"], row["logic"], row["correct"] = cfg, logic, correct
    row["required"] = bool(row["required"])
    return row


def survey_with_questions(conn, survey_id: int, shuffle_for_taker: bool = False) -> dict:
    s = _decode_survey(db.q1(conn, "SELECT * FROM surveys WHERE id=?", (survey_id,)))
    qs = [(_decode_question(q, shuffle_for_taker))
          for q in db.q(conn, "SELECT * FROM questions WHERE survey_id=? ORDER BY ordr", (survey_id,))]
    s["questions"] = qs
    s["response_count"] = db.q1(
        conn, "SELECT COUNT(*) c FROM responses WHERE survey_id=? AND submitted_at IS NOT NULL",
        (survey_id,))["c"]
    return s


# ---------------------------------------------------------------------------
# List mine + shared
# ---------------------------------------------------------------------------
@router.get("")
def list_surveys(request: Request,
                 page: int = Query(1, ge=1), limit: int = Query(db.config.PAGE_SIZE_DEFAULT, ge=1, le=db.config.PAGE_SIZE_MAX),
                 q: str = Query("", max_length=100), conn=Depends(db.get_db)):
    user = security.user_from_request(request, conn)
    if not user:
        raise HTTPException(401, "Not authenticated.")
    where = "(s.owner_id=? OR EXISTS (SELECT 1 FROM shares sh WHERE sh.survey_id=s.id AND sh.user_id=?))"
    params: tuple = (user["id"], user["id"])
    if q:
        where += " AND s.title LIKE ?"
        params += (f"%{q}%",)
    total = db.q1(conn, f"SELECT COUNT(*) c FROM surveys s WHERE {where}", params)["c"]
    rows = db.q(conn,
        f"""SELECT s.*, (SELECT COUNT(*) FROM responses r WHERE r.survey_id=s.id AND r.submitted_at IS NOT NULL) AS response_count
            FROM surveys s WHERE {where}
            ORDER BY s.updated_at DESC LIMIT ? OFFSET ?""",
        params + (limit, (page - 1) * limit))
    return {"items": [_decode_survey(r) for r in rows], "total": total, "page": page, "limit": limit}


# ---------------------------------------------------------------------------
# Create
# ---------------------------------------------------------------------------
@router.post("", status_code=201)
def create_survey(body: SurveyIn, request: Request,
                  conn=Depends(db.get_db)):
    user = security.user_from_request(request, conn)
    if not user:
        raise HTTPException(401, "Not authenticated.")
    slug = S.unique_slug(conn, body.slug, body.title)
    sid = db.execute(conn,
        """INSERT INTO surveys (owner_id,slug,title,description,cover_image,logo,settings_json,theme_json,quiz_mode)
           VALUES (?,?,?,?,?,?,?,?,?)""",
        (user["id"], slug, body.title.strip(), body.description, body.cover_image, body.logo,
         json.dumps(body.settings, separators=(",", ":")), json.dumps(body.theme, separators=(",", ":")),
         int(body.quiz_mode)))
    _replace_questions(conn, sid, body.questions)
    return survey_with_questions(conn, sid)


# ---------------------------------------------------------------------------
# Read (owner/edit-share holders)
# ---------------------------------------------------------------------------
@router.get("/{survey_id}")
def get_survey(survey_id: int, request: Request, conn=Depends(db.get_db)):
    user = security.user_from_request(request, conn)
    s = S.get_survey_or_404(conn, survey_id)
    level = S.access_level(conn, s, user)
    if not level:
        raise HTTPException(403, "You do not have access to this survey.")
    out = survey_with_questions(conn, survey_id)
    out["my_access"] = level
    return out


# ---------------------------------------------------------------------------
# Update (full replace of questions inside one transaction)
# ---------------------------------------------------------------------------
@router.put("/{survey_id}")
def update_survey(survey_id: int, body: SurveyIn, request: Request,
                  conn=Depends(db.get_db)):
    user = security.user_from_request(request, conn)
    s = S.get_survey_or_404(conn, survey_id)
    S.require_access(conn, s, user, "edit")
    slug = S.unique_slug(conn, body.slug or s["slug"], body.title, survey_id=survey_id)
    # Guard: never destroy questions that already have submitted responses.
    keep_ids = {q.id for q in body.questions if q.id}
    answered = {r["question_id"] for r in db.q(
        conn, """SELECT DISTINCT a.question_id FROM answers a JOIN responses r ON r.id=a.response_id
                 WHERE r.survey_id=? AND r.submitted_at IS NOT NULL""", (survey_id,))}
    removed_with_data = answered - keep_ids
    if removed_with_data:
        raise HTTPException(422, "Cannot remove questions that already have responses.")
    conn.execute("BEGIN")
    try:
        conn.execute(
            """UPDATE surveys SET title=?,description=?,cover_image=?,logo=?,settings_json=?,
               theme_json=?,quiz_mode=?,slug=?,updated_at=datetime('now') WHERE id=?""",
            (body.title.strip(), body.description, body.cover_image, body.logo,
             json.dumps(body.settings, separators=(",", ":")), json.dumps(body.theme, separators=(",", ":")),
             int(body.quiz_mode), slug, survey_id))
        _replace_questions(conn, survey_id, body.questions)
        conn.execute("COMMIT")
    except Exception:
        conn.execute("ROLLBACK")
        raise
    return survey_with_questions(conn, survey_id)


def _replace_questions(conn, survey_id: int, questions: list) -> None:
    keep_ids = {q.id for q in questions if q.id}
    existing = [r["id"] for r in db.q(conn, "SELECT id FROM questions WHERE survey_id=?", (survey_id,))]
    # Delete only rows the builder dropped.  Deleting a question cascades to
    # its answers — so we also guard below: never remove a question that
    # already has responses unless the client explicitly omitted it AND we are
    # in draft state (checked by caller via survey.published + response count).
    to_delete = [e for e in existing if e not in keep_ids]
    if to_delete:
        marks = ",".join("?" * len(to_delete))
        conn.execute(f"DELETE FROM questions WHERE id IN ({marks})", tuple(to_delete))
    for i, qin in enumerate(questions):
        S.validate_question(qin)
        params = (i, qin.type, qin.title, qin.description, int(qin.required),
                  json.dumps(qin.config, separators=(",", ":")),
                  json.dumps(qin.logic, separators=(",", ":")),
                  qin.points, json.dumps(qin.correct, separators=(",", ":")))
        if qin.id:
            conn.execute(
                """UPDATE questions SET ordr=?,type=?,title=?,description=?,required=?,
                   config_json=?,logic_json=?,points=?,correct_json=? WHERE id=? AND survey_id=?""",
                params + (qin.id, survey_id))
        else:
            conn.execute(
                """INSERT INTO questions (survey_id,ordr,type,title,description,required,
                   config_json,logic_json,points,correct_json) VALUES (?, ?,?,?,?,?,?,?,?,?)""",
                (survey_id,) + params)


# ---------------------------------------------------------------------------
# Publish / close / delete / duplicate
# ---------------------------------------------------------------------------
@router.post("/{survey_id}/publish")
def publish(survey_id: int, body: dict, request: Request,
            conn=Depends(db.get_db)):
    user = security.user_from_request(request, conn)
    s = S.get_survey_or_404(conn, survey_id)
    S.require_access(conn, s, user, "edit")
    published = bool(body.get("published", True))
    if published and not db.q1(conn, "SELECT 1 FROM questions WHERE survey_id=? LIMIT 1", (survey_id,)):
        raise HTTPException(422, "Add at least one question before publishing.")
    conn.execute("UPDATE surveys SET published=?, updated_at=datetime('now') WHERE id=?",
                 (int(published), survey_id))
    return {"published": published}


@router.post("/{survey_id}/close")
def close(survey_id: int, request: Request,
          conn=Depends(db.get_db)):
    user = security.user_from_request(request, conn)
    s = S.get_survey_or_404(conn, survey_id)
    S.require_access(conn, s, user, "edit")
    conn.execute("UPDATE surveys SET closed=1, updated_at=datetime('now') WHERE id=?", (survey_id,))
    return {"closed": True}


@router.delete("/{survey_id}")
def delete_survey(survey_id: int, request: Request,
                  conn=Depends(db.get_db)):
    user = security.user_from_request(request, conn)
    s = S.get_survey_or_404(conn, survey_id)
    S.require_access(conn, s, user, "edit")   # admins & owners pass; editors may not delete
    if S.access_level(conn, s, user) not in ("owner",):
        raise HTTPException(403, "Only the owner (or an admin) can delete a survey.")
    conn.execute("DELETE FROM surveys WHERE id=?", (survey_id,))
    return {"deleted": True}


@router.post("/{survey_id}/duplicate", status_code=201)
def duplicate(survey_id: int, request: Request,
              conn=Depends(db.get_db)):
    """Copy survey + questions into a new draft owned by the caller."""
    user = security.user_from_request(request, conn)
    s = S.get_survey_or_404(conn, survey_id)
    S.require_access(conn, s, user, "view")
    slug = S.unique_slug(conn, "", f"{s['title']} copy")
    new_id = db.execute(conn,
        """INSERT INTO surveys (owner_id,slug,title,description,cover_image,logo,settings_json,theme_json,quiz_mode,published)
           VALUES (?,?,?,?,?,?,?,?,?,0)""",
        (user["id"], slug, f"{s['title']} (copy)", s["description"], s["cover_image"], s["logo"],
         s["settings_json"], s["theme_json"], s["quiz_mode"]))
    for q in db.q(conn, "SELECT * FROM questions WHERE survey_id=? ORDER BY ordr", (survey_id,)):
        conn.execute(
            """INSERT INTO questions (survey_id,ordr,type,title,description,required,config_json,logic_json,points,correct_json)
               VALUES (?,?,?,?,?,?,?,?,?,?)""",
            (new_id, q["ordr"], q["type"], q["title"], q["description"], q["required"],
             q["config_json"], q["logic_json"], q["points"], q["correct_json"]))
    return survey_with_questions(conn, new_id)


# ---------------------------------------------------------------------------
# Sharing
# ---------------------------------------------------------------------------
@router.get("/{survey_id}/shares")
def list_shares(survey_id: int, request: Request, conn=Depends(db.get_db)):
    user = security.user_from_request(request, conn)
    s = S.get_survey_or_404(conn, survey_id)
    S.require_access(conn, s, user, "edit")
    return {"items": db.q(conn,
        """SELECT sh.id, sh.perm, u.email, u.name FROM shares sh JOIN users u ON u.id=sh.user_id
           WHERE sh.survey_id=?""", (survey_id,))}


@router.post("/{survey_id}/shares", status_code=201)
def add_share(survey_id: int, body: ShareIn, request: Request,
              conn=Depends(db.get_db)):
    user = security.user_from_request(request, conn)
    s = S.get_survey_or_404(conn, survey_id)
    S.require_access(conn, s, user, "edit")
    target = db.q1(conn, "SELECT id FROM users WHERE email=?", (body.email.lower(),))
    if not target:
        raise HTTPException(404, "No lunaQuest user with that email. They must register first.")
    if target["id"] == s["owner_id"]:
        raise HTTPException(422, "The owner already has full access.")
    conn.execute(
        """INSERT INTO shares (survey_id,user_id,perm) VALUES (?,?,?)
           ON CONFLICT(survey_id,user_id) DO UPDATE SET perm=excluded.perm""",
        (survey_id, target["id"], body.perm))
    return {"ok": True}


@router.delete("/{survey_id}/shares/{share_id}")
def remove_share(survey_id: int, share_id: int, request: Request,
                 conn=Depends(db.get_db)):
    user = security.user_from_request(request, conn)
    s = S.get_survey_or_404(conn, survey_id)
    S.require_access(conn, s, user, "edit")
    conn.execute("DELETE FROM shares WHERE id=? AND survey_id=?", (share_id, survey_id))
    return {"ok": True}


# ---------------------------------------------------------------------------
# Public take-view: GET /api/public/surveys/{slug}  (see public.py) and
# lightweight status endpoint used by the analytics polling loop.
# ---------------------------------------------------------------------------
@router.get("/{survey_id}/status")
def survey_status(survey_id: int, request: Request, conn=Depends(db.get_db)):
    """Real-time counters without WebSockets — cheap poll every ~10 s."""
    user = security.user_from_request(request, conn)
    s = S.get_survey_or_404(conn, survey_id)
    S.require_access(conn, s, user, "results")
    cnt = db.q1(conn,
        "SELECT COUNT(*) c, MAX(submitted_at) latest FROM responses WHERE survey_id=? AND submitted_at IS NOT NULL",
        (survey_id,))
    return {"response_count": cnt["c"], "latest_response_at": cnt["latest"]}
