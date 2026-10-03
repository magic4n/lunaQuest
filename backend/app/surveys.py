"""Survey domain logic: slug generation, permission checks, validation of
question configs, quiz grading and conditional-logic evaluation.

Pure functions on plain dicts — no ORM, trivially testable, low memory.
"""
from __future__ import annotations

import random
import re
import secrets
from typing import Any

from fastapi import HTTPException

from . import db
from .schemas import _slugify

RESERVED_SLUGS = {"admin", "api", "docs", "s", "login", "register", "assets", "new", "templates"}

# ---------------------------------------------------------------------------
# Slugs
# ---------------------------------------------------------------------------
def unique_slug(conn, desired: str, title: str, survey_id: int | None = None) -> str:
    base = _slugify(desired or title) or "survey"
    if base in RESERVED_SLUGS:
        base = f"{base}-{secrets.token_hex(2)}"
    candidate, taken = base, set()
    rows = db.q(conn, "SELECT slug FROM surveys WHERE slug LIKE ?", (f"{base}%",))
    taken = {r["slug"] for r in rows}
    if survey_id is not None:
        own = db.q1(conn, "SELECT slug FROM surveys WHERE id=?", (survey_id,))
        taken.discard(own["slug"] if own else None)
    if base not in taken:
        return base
    for _ in range(50):
        candidate = f"{base}-{secrets.token_hex(2)}"
        if candidate not in taken:
            return candidate
    raise HTTPException(409, "Could not allocate a unique URL slug.")


# ---------------------------------------------------------------------------
# Permissions
# ---------------------------------------------------------------------------
def get_survey_or_404(conn, survey_id: int) -> dict:
    s = db.q1(conn, "SELECT * FROM surveys WHERE id=?", (survey_id,))
    if not s:
        raise HTTPException(404, "Survey not found.")
    return s


def access_level(conn, survey: dict, user: dict | None) -> str | None:
    """Return 'owner' | 'edit' | 'results' | 'view' | None for this user."""
    if user is None:
        return None
    if user["role"] == "admin":
        return "owner"
    if survey["owner_id"] == user["id"]:
        return "owner"
    share = db.q1(conn, "SELECT perm FROM shares WHERE survey_id=? AND user_id=?",
                  (survey["id"], user["id"]))
    return share["perm"] if share else None


def require_access(conn, survey: dict, user: dict | None, level: str) -> None:
    """level: 'view' (anyone with any grant), 'edit', 'results'."""
    have = access_level(conn, survey, user)
    if not have:
        raise HTTPException(403, "You do not have access to this survey.")
    order = {"view": 0, "results": 1, "edit": 2, "owner": 3}
    need = {"view": 0, "results": 1, "edit": 2}[level]
    if order[have] < need:
        raise HTTPException(403, f"'{level}' permission required.")


# ---------------------------------------------------------------------------
# Question config validation (per type) — reject nonsense early.
# ---------------------------------------------------------------------------
_VALIDATORS: dict[str, list[str]] = {
    "choice_single": ["choices"], "choice_multi": ["choices"], "dropdown": ["choices"],
    "ranking": ["choices"],
    "linear_scale": [], "rating": [], "slider": [],
    "grid_single": ["rows", "cols"], "grid_multi": ["rows", "cols"], "matrix": ["rows", "cols"],
    "image": ["src"], "video": ["url"],
    "number": [], "short_text": [], "long_text": [], "email": [], "url": [], "phone": [],
    "date": [], "time": [], "datetime": [], "file": [], "yes_no": [],
    "section": [], "page_break": [],
}


def validate_question(qin) -> None:
    cfg = qin.config or {}
    t = qin.type
    for field_name in _VALIDATORS.get(t, []):
        if field_name in ("src", "url"):
            if t in ("image", "video") and not str(cfg.get(field_name, "")).strip():
                raise HTTPException(422, f"'{field_name}' is required for {t} questions.")
            continue
        vals = cfg.get(field_name)
        if not isinstance(vals, list) or len(vals) < (1 if field_name != "choices" else 2):
            raise HTTPException(422, f"Question type '{t}' needs at least "
                                     f"{2 if field_name=='choices' else 1} entries in '{field_name}'.")
    if t in ("image", "video"):
        src = str(cfg.get("src") or cfg.get("url") or "")
        if src.startswith("javascript:") or src.startswith("data:text/html"):
            raise HTTPException(422, "Unsafe media URL scheme.")
    if t == "video":
        url = str(cfg.get("url", ""))
        if not re.match(r"^https://(www\.)?(youtube\.com|youtu\.be|vimeo\.com)/", url):
            raise HTTPException(422, "Video embed supports YouTube and Vimeo only.")
    if t in ("linear_scale", "slider", "number"):
        lo, hi = cfg.get("min"), cfg.get("max")
        if lo is not None and hi is not None and float(lo) >= float(hi):
            raise HTTPException(422, "'min' must be lower than 'max'.")
    # Regex validation rule (applies to text-ish types)
    rx = cfg.get("regex")
    if rx:
        try:
            re.compile(rx)
        except re.error:
            raise HTTPException(422, "Invalid regular expression in validation rules.")


# ---------------------------------------------------------------------------
# Answer value normalization + required/validation checks at submit time.
# Value shapes:
#   short_text/long_text/email/url/phone : str
#   number/slider/linear_scale/rating    : number
#   choice_single/dropdown/yes_no        : str  ("other:<text>" allowed)
#   choice_multi/ranking                 : list[str]
#   date/time/datetime                   : str ISO
#   grid_single                          : {row: col}      grid_multi/matrix: {row: [cols]}
#   file                                 : {name,url,size}| list thereof
#   section/page_break/image/video       : null (display-only)
# ---------------------------------------------------------------------------
DISPLAY_TYPES = {"section", "page_break", "image", "video"}


def answer_is_empty(value: Any, qtype: str) -> bool:
    if qtype in DISPLAY_TYPES:
        return False
    if value is None:
        return True
    if isinstance(value, str):
        return value.strip() == ""
    if isinstance(value, (list, dict)):
        return len(value) == 0
    return False


def validate_answer_value(value: Any, qrow: dict) -> None:
    cfg = qrow.get("_config", {})
    t = qrow["type"]
    if t in ("number", "slider", "linear_scale", "rating") and value is not None and not isinstance(value, (int, float)):
        raise HTTPException(422, f"Question '{qrow['title'][:40]}': numeric answer expected.")
    if t in ("number", "slider", "linear_scale"):
        lo, hi = cfg.get("min"), cfg.get("max")
        if isinstance(value, (int, float)):
            if lo is not None and value < float(lo):
                raise HTTPException(422, "Answer below minimum.")
            if hi is not None and value > float(hi):
                raise HTTPException(422, "Answer above maximum.")
    if t in ("short_text", "long_text", "email", "url", "phone") and isinstance(value, str):
        mn, mx = cfg.get("min_length"), cfg.get("max_length")
        if mn and len(value) < int(mn):
            raise HTTPException(422, "Answer too short.")
        if mx and len(value) > int(mx):
            raise HTTPException(422, "Answer too long.")
        rx = cfg.get("regex")
        if rx and not re.search(rx, value):
            raise HTTPException(422, "Answer does not match the required pattern.")
        if t == "email" and value and not re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", value):
            raise HTTPException(422, "Invalid email address.")
        if t == "url" and value and not re.match(r"^https?://[^\s]+$", value):
            raise HTTPException(422, "Invalid URL (must start with http/https).")
        if t == "phone" and value and not re.match(r"^[+()\-\s\d.]{5,25}$", value):
            raise HTTPException(422, "Invalid phone number.")
    if t in ("choice_single", "dropdown", "yes_no", "choice_multi", "ranking") and value is not None:
        allowed = {str(c.get("value", c)) if isinstance(c, dict) else str(c)
                   for c in cfg.get("choices", [])}
        if t == "yes_no":
            allowed |= {"yes", "no"}
        if cfg.get("allow_other"):
            allowed |= {"other"}
        items = value if isinstance(value, list) else [value]
        for it in items:
            s = str(it)
            if s.startswith("other:"):
                if not cfg.get("allow_other"):
                    raise HTTPException(422, "'Other' answers are not allowed here.")
                continue
            if allowed and s not in allowed:
                raise HTTPException(422, f"Unexpected option '{s[:40]}'.")
        if t in ("choice_single", "dropdown", "yes_no") and isinstance(value, list) and len(value) > 1:
            raise HTTPException(422, "Single-answer question received multiple values.")
    if t in ("grid_single", "grid_multi", "matrix") and isinstance(value, dict):
        rows = {str(r) for r in cfg.get("rows", [])}
        cols = {str(c) for c in cfg.get("cols", [])}
        for r, v in value.items():
            if rows and str(r) not in rows:
                raise HTTPException(422, f"Unknown grid row '{r}'.")
            vs = v if isinstance(v, list) else [v]
            for c in vs:
                if cols and str(c) not in cols:
                    raise HTTPException(422, f"Unknown grid column '{c}'.")
    if t == "file" and isinstance(value, dict):
        if not value.get("url", "").startswith("/api/uploads/"):
            raise HTTPException(422, "File answer must reference an uploaded file.")


# ---------------------------------------------------------------------------
# Quiz grading — returns (score, max_score)
# ---------------------------------------------------------------------------
def grade_quiz(questions: list[dict], answers: dict[int, Any]) -> tuple[float | None, float]:
    total_max = sum(float(q["points"]) for q in questions if q["points"] and q["correct_json"] != "null")
    if total_max <= 0:
        return None, 0.0
    score = 0.0
    for q in questions:
        if not q["points"] or q["correct_json"] == "null":
            continue
        correct = q["_correct"]
        got = answers.get(q["id"])
        if _answer_matches(got, correct, q["type"]):
            score += float(q["points"])
    return round(score, 4), total_max


def _norm(x: Any) -> Any:
    if isinstance(x, str):
        return x.strip().lower()
    if isinstance(x, list):
        return sorted(_norm(i) for i in x)
    if isinstance(x, dict):
        return {str(k): _norm(v) for k, v in x.items()}
    return x


def _answer_matches(got: Any, correct: Any, qtype: str) -> bool:
    if qtype in ("choice_multi", "grid_multi", "matrix", "ranking"):
        # ranking compares exact order; multi-choice compares sets
        if qtype == "ranking":
            return _norm(got) == _norm(correct)
        g, c = _as_set_list(got, qtype), _as_set_list(correct, qtype)
        return g == c
    if qtype in ("grid_single",):
        return _norm(got) == _norm(correct)
    if isinstance(correct, (int, float)) and isinstance(got, (int, float)):
        tol = 1e-6
        return abs(float(got) - float(correct)) < tol
    return _norm(got) == _norm(correct)


def _as_set_list(val: Any, qtype: str) -> Any:
    if qtype in ("grid_multi", "matrix") and isinstance(val, dict):
        return {k: sorted(str(x).lower() for x in (v if isinstance(v, list) else [v]))
                for k, v in val.items()}
    if isinstance(val, list):
        return sorted(str(x).lower() for x in val)
    return val


# ---------------------------------------------------------------------------
# Conditional logic — evaluated client-side for UX, but the server ALSO
# applies skip/show rules when enforcing `required` so hidden questions
# don't block submissions.
# ---------------------------------------------------------------------------
def evaluate_rule(rule: dict, prev_answers: dict[int, Any], qid_map: dict[int, int]) -> bool:
    """Does `rule` fire given collected answers?  qid_map: index->id."""
    src = rule.get("source_ord")           # ordinal of source question
    if src is None or src not in qid_map:
        return False
    val = prev_answers.get(qid_map[src])
    op = rule.get("op", "eq")
    target = rule.get("value")
    if op == "answered":
        return not answer_is_empty(val, "short_text")
    if op == "unanswered":
        return answer_is_empty(val, "short_text")
    sval = str(val) if val is not None else ""
    if op == "eq":
        return sval == str(target)
    if op == "neq":
        return sval != str(target)
    if op == "contains":
        if isinstance(val, list):
            return str(target) in [str(v) for v in val]
        return str(target).lower() in sval.lower()
    if op == "any_of":
        opts = {str(t) for t in (target or [])}
        vals = val if isinstance(val, list) else [val]
        return any(str(v) in opts for v in vals)
    try:
        f = float(val)
        ft = float(target)
        if op == "gt":
            return f > ft
        if op == "lt":
            return f < ft
    except (TypeError, ValueError):
        return False
    return False


def visible_questions(questions: list[dict], answers: dict[int, Any]) -> list[dict]:
    """Server-side mirror of the branching engine: which questions apply?"""
    ordinals = {q["id"]: i for i, q in enumerate(questions)}
    out: list[dict] = []
    skip_until = -1
    for i, q in enumerate(questions):
        if i < skip_until:
            continue
        show = True
        for rule in q["_logic"]:
            fires = evaluate_rule(rule, answers, ordinals)
            action = rule.get("action")
            if action == "hide" and fires:
                show = False
            elif action == "show" and not fires:
                show = False
            elif action == "skip_to" and fires:
                tgt = rule.get("target_ord")
                if tgt is not None and tgt > i:
                    skip_until = tgt
        if show:
            out.append(q)
    return out


def shuffle_choices(config: dict) -> dict:
    """Randomize choice order when requested (server seed per render)."""
    if config.get("randomize") and isinstance(config.get("choices"), list):
        ch = list(config["choices"])
        random.shuffle(ch)
        config = {**config, "choices": ch}
    return config
