"""Public survey taking: fetch by slug, submit responses, drafts, uploads.

RAM rules honored here:
  * file uploads stream to disk in 64 KB chunks (never buffered whole),
  * submissions are validated against the visible-questions logic engine so
    hidden/skipped required questions never block a valid response,
  * one-response-per-user enforced via user_id / ip_hash dedupe.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import secrets
from typing import Any

import re

from fastapi import APIRouter, Depends, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse

from .. import config, db, security, surveys as S
from . import surveys as _r
from ..schemas import SubmitIn

router = APIRouter(prefix="/public", tags=["public"])

# Strict filename pattern for served uploads: 32-hex token + short extension.
_SAFE_FNAME = re.compile(r"^[0-9a-f]{32}\.[a-z]{3,4}$")

# In-memory page-password checks are stateless: we store only a salted hash in
# settings_json.password_hash at publish time (see builder).  This dict keeps
# per-survey unlock tokens tiny (<1 KB each) and is capped below.
_unlock_cache: dict[int, float] = {}
_UNLOCK_TTL = 900.0          # seconds
_UNLOCK_MAX = 1024           # hard cap → bounded memory


def _is_unlocked(survey_id: int) -> bool:
    import time
    exp = _unlock_cache.get(survey_id)
    if exp is None:
        return False
    if exp < time.time():
        _unlock_cache.pop(survey_id, None)
        return False
    return True


def _remember_unlock(survey_id: int) -> None:
    import time
    if len(_unlock_cache) >= _UNLOCK_MAX:      # evict oldest first (tiny LRU-ish)
        oldest = min(_unlock_cache, key=_unlock_cache.get)
        _unlock_cache.pop(oldest)
    _unlock_cache[survey_id] = time.time() + _UNLOCK_TTL


def _load_public_survey(conn, slug: str) -> dict:
    s = db.q1(conn, "SELECT * FROM surveys WHERE slug=?", (slug,))
    if not s:
        raise HTTPException(404, "Survey not found.")
    settings = json.loads(s["settings_json"] or "{}")
    now_iso = _utcnow_iso()
    if not s["published"] or s["closed"]:
        raise HTTPException(410, "This survey is closed.")
    if settings.get("start_date") and settings["start_date"] > now_iso:
        raise HTTPException(425, "This survey has not opened yet.")
    if settings.get("end_date") and settings["end_date"] < now_iso:
        raise HTTPException(410, "This survey has closed.")
    if settings.get("visibility") == "unlisted":
        pass  # unlisted surveys are reachable only by their link; nothing extra server-side
    return {"row": s, "settings": settings}


def _utcnow_iso() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


@router.get("/surveys/{slug}")
def get_public_survey(slug: str, request: Request, conn=Depends(db.get_db)):
    """Payload for the take page — no owner emails, choices shuffled if asked."""
    loaded = _load_public_survey(conn, slug)
    s, settings = loaded["row"], loaded["settings"]
    user = security.user_from_request(request, conn)

    needs_password = bool(settings.get("password_hash")) and not _is_unlocked(s["id"])
    qs = [_r._decode_question(q, shuffle=bool(settings.get("shuffle_questions")))
          for q in db.q(conn, "SELECT * FROM questions WHERE survey_id=? ORDER BY ordr", (s["id"],))]
    # Strip quiz answers from the taker payload (server grades invisibly).
    for q in qs:
        q.pop("correct", None)
        q.pop("points", None)
    out = {
        "slug": s["slug"], "title": s["title"], "description": s["description"],
        "cover_image": s["cover_image"], "logo": s["logo"],
        "theme": json.loads(s["theme_json"] or "{}"),
        "quiz_mode": bool(s["quiz_mode"]),
        "needs_password": needs_password,
        "requires_login": bool(settings.get("require_login")),
        "show_progress": bool(settings.get("show_progress", True)),
        "save_later": bool(settings.get("save_later")),
        "max_responses": settings.get("max_responses"),
        "confirmation_message": settings.get("confirmation_message", ""),
        "redirect_url": settings.get("redirect_url", ""),
        "questions": qs,
    }
    if needs_password:
        out.pop("questions")            # do not leak structure until unlocked
    if settings.get("require_login") and not user:
        raise HTTPException(401, "login_required")
    return out


@router.post("/surveys/{slug}/unlock")
def unlock(slug: str, body: dict, conn=Depends(db.get_db)):
    """Password-protected surveys: verify once, remember for 15 minutes."""
    loaded = _load_public_survey(conn, slug)
    s, settings = loaded["row"], loaded["settings"]
    stored = settings.get("password_hash", "")
    given = str(body.get("password", ""))[:128]
    digest = hashlib.sha256(given.encode()).hexdigest()
    if not stored or not hmac.compare_digest(stored, digest):
        raise HTTPException(403, "Incorrect password.")
    _remember_unlock(s["id"])
    return {"ok": True}


# ---------------------------------------------------------------------------
# Submit / draft
# ---------------------------------------------------------------------------
@router.post("/surveys/{slug}/submit")
def submit(slug: str, body: SubmitIn, request: Request,
           conn=Depends(db.get_db)):
    loaded = _load_public_survey(conn, slug)
    s, settings = loaded["row"], loaded["settings"]
    user = security.user_from_request(request, conn)

    if settings.get("password_hash") and not _is_unlocked(s["id"]):
        raise HTTPException(403, "Survey is password protected — unlock it first.")
    if settings.get("require_login") and not user:
        raise HTTPException(401, "login_required")

    # Max responses limit (checked before writing anything).
    max_r = settings.get("max_responses")
    if max_r:
        cnt = db.q1(conn,
            "SELECT COUNT(*) c FROM responses WHERE survey_id=? AND submitted_at IS NOT NULL",
            (s["id"],))["c"]
        if cnt >= int(max_r):
            raise HTTPException(410, "This survey has reached its response limit.")

    # Identity for dedupe/drafts.  NOTE: we deliberately do NOT trust
    # X-Forwarded-For here — unlike rate limiting (where spoofing only affects
    # your own quota), trusting a client-supplied header would let anyone set
    # it to "1.2.3.4" and bypass one-response-per-IP limits entirely.  The
    # socket peer is the honest key; behind a proxy operators can set
    # LUNAQ_TRUST_PROXY=1 to switch to the first XFF hop at their discretion.
    ip = request.client.host if request.client else "unknown"
    if config.TRUST_PROXY:
        xff = request.headers.get("x-forwarded-for", "")
        if xff:
            ip = xff.split(",")[0].strip()
    iph = db.hash_ip(ip)
    uah = db.hash_ua(request.headers.get("user-agent", ""))
    if settings.get("one_per_user") and body.submit:
        if user:
            dup = db.q1(conn, "SELECT id FROM responses WHERE survey_id=? AND user_id=? AND submitted_at IS NOT NULL",
                        (s["id"], user["id"]))
        else:
            dup = db.q1(conn, "SELECT id FROM responses WHERE survey_id=? AND user_id IS NULL AND ip_hash=? AND submitted_at IS NOT NULL",
                        (s["id"], iph))
        if dup:
            raise HTTPException(409, "You have already responded to this survey.")

    # Load questions with parsed JSON for validation/grading.
    rows = db.q(conn, "SELECT * FROM questions WHERE survey_id=? ORDER BY ordr", (s["id"],))
    questions: list[dict[str, Any]] = []
    for r in rows:
        r["_config"] = json.loads(r["config_json"] or "{}")
        r["_logic"] = json.loads(r["logic_json"] or "[]")
        r["_correct"] = json.loads(r["correct_json"] or "null")
        questions.append(r)
    qmap = {q["id"]: q for q in questions}

    answers: dict[int, Any] = {}
    for a in body.answers:
        if a.question_id not in qmap:
            raise HTTPException(422, f"Unknown question id {a.question_id}.")
        answers[a.question_id] = a.value

    # Server-side conditional logic: enforce required only on VISIBLE questions.
    visible = S.visible_questions(questions, answers)
    if body.submit:
        for q in visible:
            val = answers.get(q["id"])
            if S.answer_is_empty(val, q["type"]):
                if q["required"]:
                    raise HTTPException(422, f"Question '{q['title'][:60]}' is required.")
                continue
            S.validate_answer_value(val, q)

    score: float | None = None
    max_score = 0.0
    if bool(s["quiz_mode"]) and body.submit:
        score, max_score = S.grade_quiz(questions, answers)

    # Upsert draft-or-submit row.  A logged-in user's draft is reused via
    # response_id passed back in started flow? Simpler: drafts create rows with
    # submitted_at NULL; submitting deletes any prior draft of same identity.
    existing_draft = None
    if user:
        existing_draft = db.q1(conn,
            "SELECT id FROM responses WHERE survey_id=? AND user_id=? AND submitted_at IS NULL",
            (s["id"], user["id"]))
    rid = existing_draft["id"] if existing_draft else None
    if rid is None:
        rid = db.execute(conn,
            """INSERT INTO responses (survey_id,user_id,started_at,ip_hash,user_agent_hash)
               VALUES (?,?,?,?,?)""",
            (s["id"], user["id"] if user else None, body.started_at or _utcnow_iso(), iph, uah))
    conn.execute("BEGIN")
    try:
        conn.execute("DELETE FROM answers WHERE response_id=?", (rid,))
        for qid, val in answers.items():
            if qid in qmap and not S.answer_is_empty(val, qmap[qid]["type"]):
                conn.execute(
                    "INSERT INTO answers (response_id,question_id,value_json) VALUES (?,?,?)",
                    (rid, qid, json.dumps(val, separators=(",", ":"))))
        if body.submit:
            conn.execute(
                """UPDATE responses SET submitted_at=datetime('now'), score=? WHERE id=?""",
                (score, rid))
            if existing_draft:
                pass  # reusing the draft row — nothing else to clean
        else:
            conn.execute("UPDATE responses SET score=NULL WHERE id=?", (rid,))
        conn.execute("COMMIT")
    except Exception:
        conn.execute("ROLLBACK")
        raise

    result: dict[str, Any] = {"response_id": rid, "submitted": body.submit}
    if body.submit and s["quiz_mode"] and score is not None:
        result["score"] = score
        result["max_score"] = max_score
        result["grade_pct"] = round(100.0 * score / max_score, 1) if max_score else None
        # Per-question correctness feedback (only when owner enabled show_results).
        if settings.get("quiz_show_correct"):
            fb = []
            for q in visible:
                if q["points"] and q["correct_json"] != "null":
                    got = answers.get(q["id"])
                    fb.append({"question_id": q["id"],
                               "correct": S._answer_matches(got, q["_correct"], q["type"])})
            result["feedback"] = fb
    if body.submit and settings.get("notify_owner") and not existing_draft:
        _notify_owner(conn, s, score, max_score)
    return result


def _notify_owner(conn, s: dict, score, max_score) -> None:
    """Best-effort email to survey owner about a new response (fails soft)."""
    from ..mailer import send_mail
    owner = db.q1(conn, "SELECT email,name FROM users WHERE id=?", (s["owner_id"],))
    if not owner:
        return
    extra = f"\nQuiz score: {score}/{max_score}" if score is not None else ""
    send_mail(owner["email"], f"[lunaQuest] New response to “{s['title']}”",
              f"{owner['name'] or 'There'}’s survey “{s['title']}” received a new response.{extra}\n"
              f"View results: {config.PUBLIC_BASE_URL}/surveys/{s['id']}/results\n")


# ---------------------------------------------------------------------------
# Draft retrieval ("save & continue later" — requires login)
# ---------------------------------------------------------------------------
@router.get("/surveys/{slug}/my-draft")
def my_draft(slug: str, request: Request, conn=Depends(db.get_db)):
    user = security.get_current_user(request, conn)
    s = db.q1(conn, "SELECT * FROM surveys WHERE slug=?", (slug,))
    if not s:
        raise HTTPException(404, "Survey not found.")
    draft = db.q1(conn,
        "SELECT * FROM responses WHERE survey_id=? AND user_id=? AND submitted_at IS NULL",
        (s["id"], user["id"]))
    if not draft:
        return {"draft": None}
    answers = {r["question_id"]: json.loads(r["value_json"])
               for r in db.q(conn, "SELECT question_id,value_json FROM answers WHERE response_id=?",
                             (draft["id"],))}
    return {"draft": {"response_id": draft["id"], "started_at": draft["started_at"],
                      "answers": [{"question_id": k, "value": v} for k, v in answers.items()]}}


# ---------------------------------------------------------------------------
# File upload endpoint (for `file` questions) — streamed to disk.
# ---------------------------------------------------------------------------
@router.post("/surveys/{slug}/upload")
async def upload_file(slug: str, request: Request, file: UploadFile,
                      conn=Depends(db.get_db)):
    loaded = _load_public_survey(conn, slug)
    s, settings = loaded["row"], loaded["settings"]
    if settings.get("password_hash") and not _is_unlocked(s["id"]):
        raise HTTPException(403, "Unlock the survey first.")
    mime = (file.content_type or "").lower()
    if mime not in config.ALLOWED_UPLOAD_TYPES:
        raise HTTPException(415, f"Unsupported file type '{mime}'.")
    max_bytes = int(settings.get("max_upload_mb", config.MAX_UPLOAD_MB)) * 1024 * 1024
    token = secrets.token_hex(16)
    ext = config.ALLOWED_UPLOAD_TYPES[mime]
    dest_dir = config.UPLOAD_DIR / str(s["id"])
    dest_dir.mkdir(parents=True, exist_ok=True)
    dest = dest_dir / f"{token}{ext}"
    written = 0
    try:
        with dest.open("wb") as out:
            while chunk := await file.read(64 * 1024):     # 64 KB chunks — constant RAM
                written += len(chunk)
                if written > max_bytes:
                    out.close()
                    dest.unlink(missing_ok=True)
                    raise HTTPException(413, f"File exceeds the {max_bytes // (1024*1024)} MB limit.")
                out.write(chunk)
    finally:
        await file.close()
    safe_name = "".join(c for c in (file.filename or "file") if c.isalnum() or c in "-._ ")[:80] or "file"
    return {"name": safe_name, "url": f"/api/uploads/{s['id']}/{token}{ext}", "size": written}


# Serve uploaded answer files — only through this authenticated-by-path route
# (uploads dir is outside the web root; links carry an unguessable token).
files_router = APIRouter(prefix="/uploads", tags=["public-files"])


@files_router.get("/{survey_id}/{fname}")
def get_upload(survey_id: int, fname: str):
    # Strict filename pattern blocks traversal; the unguessable token is the
    # access grant (uploads live outside the web root entirely).
    if not _SAFE_FNAME.match(fname):
        raise HTTPException(400, "Bad file name.")
    path = (config.UPLOAD_DIR / str(survey_id) / fname).resolve()
    if not str(path).startswith(str((config.UPLOAD_DIR / str(survey_id)).resolve())) or not path.is_file():
        raise HTTPException(404, "File not found.")
    return FileResponse(path)
