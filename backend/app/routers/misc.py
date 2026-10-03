"""API keys (per-user programmatic access) + public site info + templates."""
from __future__ import annotations
from fastapi import APIRouter, Depends, HTTPException, Request
from .. import db, security
from ..schemas import ApiKeyIn
router = APIRouter(prefix="/me/api-keys", tags=["api-keys"])
@router.get("")
def list_keys(user=Depends(security.get_current_user), conn=Depends(db.get_db)):
    rows = db.q(conn,
        "SELECT id,label,prefix,created_at,last_used FROM api_keys WHERE user_id=? ORDER BY created_at DESC",
        (user["id"],))
    return {"items": rows}
@router.post("", status_code=201)
def create_key(body: ApiKeyIn, request: Request,
               user=Depends(security.get_current_user), conn=Depends(db.get_db)):
    raw, key_hash = security.generate_api_key()
    db.execute(conn, "INSERT INTO api_keys (user_id,label,key_hash,prefix) VALUES (?,?,?,?)",
               (user["id"], body.label.strip(), key_hash, raw[:12]))
    # The raw secret is returned exactly once — only the hash is stored.
    return {"key": raw, "prefix": raw[:12], "warning": "Copy it now; it will not be shown again."}
@router.delete("/{key_id}")
def revoke_key(key_id: int, request: Request,
               user=Depends(security.get_current_user), conn=Depends(db.get_db)):
    conn.execute("DELETE FROM api_keys WHERE id=? AND user_id=?", (key_id, user["id"]))
    return {"ok": True}
# ---------------------------------------------------------------------------
# Public site info (no auth) — powers the header title & registration toggle.
# ---------------------------------------------------------------------------
site_router = APIRouter(tags=["public-site"])
@site_router.get("/site-info")
def site_info(conn=Depends(db.get_db)):
    rows = {r["key"]: r["value"] for r in db.q(conn, "SELECT key,value FROM settings")}
    return {
        "site_name": rows.get("site_name", "lunaQuest"),
        "registration_open": rows.get("registration_open", "1") != "0",
        "require_email_verification": rows.get("require_email_verification", "0") == "1",
    }
# ---------------------------------------------------------------------------
# Templates gallery — built-in, language-aware via Accept-Language fallback EN.
# Each template is a question blueprint the SPA expands into a new survey.
# ---------------------------------------------------------------------------
TEMPLATES: dict[str, list[dict]] = {
    "blank": [],
    "feedback": [
        {"type": "rating", "title": "Overall experience", "config": {"icon": "stars", "max": 5}, "required": True},
        {"type": "linear_scale", "title": "How likely are you to recommend us?",
         "config": {"min": 0, "max": 10, "min_label": "Not likely", "max_label": "Very likely"}, "required": True},
        {"type": "choice_multi", "title": "What did you like?",
         "config": {"choices": ["Design", "Speed", "Support", "Price", "Features"]}},
        {"type": "long_text", "title": "Anything else we should know?", "config": {"placeholder": "Your thoughts…"}},
    ],
    "rsvp": [
        {"type": "short_text", "title": "Name", "required": True},
        {"type": "email", "title": "Email", "required": True},
        {"type": "yes_no", "title": "Will you attend?", "required": True},
        {"type": "number", "title": "Number of guests", "config": {"min": 0, "max": 10}},
        {"type": "long_text", "title": "Dietary requirements"},
    ],
    "quiz": [
        {"type": "choice_single", "title": "What does HTML stand for?",
         "config": {"choices": ["HyperText Markup Language", "High Tech Modern Language", "Home Tool Markup Language"]},
         "correct": "HyperText Markup Language", "points": 1, "required": True},
        {"type": "choice_single", "title": "Which planet is known as the Red Planet?",
         "config": {"choices": ["Venus", "Mars", "Jupiter"]},
         "correct": "Mars", "points": 1, "required": True},
        {"type": "dropdown", "title": "Largest ocean on Earth?",
         "config": {"choices": ["Atlantic", "Indian", "Pacific"]},
         "correct": "Pacific", "points": 1, "required": True},
        {"type": "number", "title": "How many continents are there?",
         "config": {"min": 1, "max": 12}, "correct": 7, "points": 2, "required": True},
    ],
    "registration": [
        {"type": "section", "title": "About you", "description": "Tell us who you are."},
        {"type": "short_text", "title": "Full name", "required": True},
        {"type": "email", "title": "Email address", "required": True},
        {"type": "phone", "title": "Phone number"},
        {"type": "dropdown", "title": "Role",
         "config": {"choices": ["Student", "Engineer", "Designer", "Manager", "Other"], "allow_other": True}},
        {"type": "date", "title": "Start date", "required": True},
    ],
    "nps": [
        {"type": "linear_scale", "title": "How likely are you to recommend us to a friend or colleague?",
         "config": {"min": 0, "max": 10, "min_label": "Not at all likely", "max_label": "Extremely likely"},
         "required": True},
        {"type": "long_text", "title": "What is the primary reason for your score?", "required": True},
    ],
    "event_eval": [
        {"type": "date", "title": "Which event did you attend?", "required": True},
        {"type": "grid_single", "title": "Rate each aspect",
         "config": {"rows": ["Venue", "Content", "Catering", "Networking"],
                    "cols": ["Poor", "Fair", "Good", "Excellent"]}, "required": True},
        {"type": "slider", "title": "Value for money (0–100)",
         "config": {"min": 0, "max": 100, "step": 5}},
        {"type": "choice_multi", "title": "Would you come back for?",
         "config": {"choices": ["Talks", "Workshops", "Social events", "Exhibitions"]}},
    ],
}
templates_router = APIRouter(prefix="/templates", tags=["templates"])
@templates_router.get("")
def list_templates():
    """Template ids + localized display names resolved from i18n keys client-side."""
    return {"items": [{"id": tid, "question_count": len(qs)} for tid, qs in TEMPLATES.items()]}
@templates_router.get("/{template_id}")
def get_template(template_id: str):
    if template_id not in TEMPLATES:
        raise HTTPException(404, "Unknown template.")
    return {"id": template_id, "questions": TEMPLATES[template_id]}
