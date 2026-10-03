"""Responses: paginated table, single view, delete, summary analytics, and
streaming CSV/JSON exports.

Memory rules honored:
  * every list endpoint paginates (default 25 / max 100),
  * CSV export streams row-by-row through a generator — O(page) memory even
    for hundreds of thousands of responses,
  * aggregate charts are computed with SQL + small Python passes over one
    question's answers at a time (never the whole response set).
"""
from __future__ import annotations

import csv
import io
import json
from collections import Counter
from typing import Any, Iterator

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import StreamingResponse

from .. import config, db, security, surveys as S

router = APIRouter(prefix="/surveys/{survey_id}/responses", tags=["responses"])


def _require_results(conn, survey_id: int, request: Request) -> dict:
    user = security.user_from_request(request, conn)
    s = S.get_survey_or_404(conn, survey_id)
    S.require_access(conn, s, user, "results")
    return s


# ---------------------------------------------------------------------------
# Static sub-paths (/summary/stats, /export/csv, /export/json) live on their
# own router so they are matched BEFORE the "/{response_id}" parameter route —
# FastAPI evaluates routes in registration order.  main.py includes this
# `static_router` first.
# ---------------------------------------------------------------------------
static_router = APIRouter(prefix="/surveys/{survey_id}/responses", tags=["responses"])


@router.get("")
def list_responses(survey_id: int, request: Request,
                   page: int = Query(1, ge=1),
                   limit: int = Query(db.config.PAGE_SIZE_DEFAULT, ge=1, le=db.config.PAGE_SIZE_MAX),
                   sort: str = Query("submitted_at", pattern="^(submitted_at|started_at|score|id)$"),
                   direction: str = Query("desc", pattern="^(asc|desc)$"),
                   q: str = Query("", max_length=200),
                   date_from: str = Query("", max_length=32),
                   date_to: str = Query("", max_length=32),
                   answered_q: int | None = Query(None),
                   answered_value: str = Query("", max_length=200),
                   drafts: bool = Query(False),
                   conn=Depends(db.get_db)):
    """Paginated, filterable, sortable responses table."""
    _require_results(conn, survey_id, request)
    where = ["r.survey_id=?", "" if drafts else "r.submitted_at IS NOT NULL"]
    params: list[Any] = [survey_id]
    if not drafts:
        params = [survey_id]
    if q:
        # Free-text search across answer values (indexed by survey first).
        where.append("""EXISTS (SELECT 1 FROM answers a JOIN questions qq ON qq.id=a.question_id
                        WHERE a.response_id=r.id AND (qq.title LIKE ? OR a.value_json LIKE ?))""")
        params += [f"%{q}%", f"%{q}%"]
    if date_from:
        where.append("COALESCE(r.submitted_at, r.started_at) >= ?")
        params.append(date_from)
    if date_to:
        where.append("COALESCE(r.submitted_at, r.started_at) <= ?")
        params.append(date_to + "T23:59:59" if len(date_to) == 10 else date_to)
    if answered_q is not None and answered_value:
        where.append("""EXISTS (SELECT 1 FROM answers a WHERE a.response_id=r.id
                        AND a.question_id=? AND a.value_json LIKE ?)""")
        params += [answered_q, f'%"{answered_value}"%']
    wsql = " AND ".join(x for x in where if x)
    total = db.q1(conn, f"SELECT COUNT(*) c FROM responses r WHERE {wsql}", tuple(params))["c"]
    rows = db.q(conn,
        f"""SELECT r.*, u.email AS user_email,
                   (SELECT COUNT(*) FROM answers a WHERE a.response_id=r.id) AS answer_count
            FROM responses r LEFT JOIN users u ON u.id=r.user_id
            WHERE {wsql} ORDER BY r.{sort} {direction.upper()} LIMIT ? OFFSET ?""",
        tuple(params) + (limit, (page - 1) * limit))
    return {"items": rows, "total": total, "page": page, "limit": limit}


@router.get("/{response_id}")
def get_response(survey_id: int, response_id: int, request: Request, conn=Depends(db.get_db)):
    _require_results(conn, survey_id, request)
    r = db.q1(conn, "SELECT * FROM responses WHERE id=? AND survey_id=?", (response_id, survey_id))
    if not r:
        raise HTTPException(404, "Response not found.")
    answers = []
    for a in db.q(conn,
        """SELECT a.*, q.ordr, q.type, q.title FROM answers a JOIN questions q ON q.id=a.question_id
           WHERE a.response_id=? ORDER BY q.ordr""", (response_id,)):
        a["value"] = json.loads(a.pop("value_json"))
        answers.append(a)
    r["answers"] = answers
    return r


@router.delete("/{response_id}")
def delete_response(survey_id: int, response_id: int, request: Request, conn=Depends(db.get_db)):
    _require_results(conn, survey_id, request)
    conn.execute("DELETE FROM responses WHERE id=? AND survey_id=?", (response_id, survey_id))
    return {"deleted": True}


# ---------------------------------------------------------------------------
# Summary analytics — per-question aggregates computed on the server so the
# SPA can render M3 charts without shipping all raw data to the client.
# ---------------------------------------------------------------------------
@static_router.get("/summary/stats")
def summary(survey_id: int, request: Request, conn=Depends(db.get_db)):
    _require_results(conn, survey_id, request)
    questions = db.q(conn, "SELECT id,type,title,config_json FROM questions WHERE survey_id=? ORDER BY ordr",
                     (survey_id,))
    counts = db.q1(conn,
        "SELECT COUNT(*) submitted, SUM(CASE WHEN submitted_at IS NULL THEN 1 ELSE 0 END) drafts "
        "FROM responses WHERE survey_id=?", (survey_id,))
    stats: list[dict[str, Any]] = []
    # One question's answers are loaded and aggregated at a time; between
    # questions the memory is released — bounded even for huge surveys.
    for q in questions:
        cfg = json.loads(q["config_json"] or "{}")
        values = [json.loads(v[0]) for v in conn.execute(
            """SELECT a.value_json FROM answers a JOIN responses r ON r.id=a.response_id
               WHERE a.question_id=? AND r.submitted_at IS NOT NULL""", (q["id"],)).fetchall()]
        stats.append(_question_stats(q, cfg, values))
    timeline = db.q(conn,
        """SELECT substr(COALESCE(submitted_at, started_at),1,10) AS day, COUNT(*) c
           FROM responses WHERE survey_id=? AND submitted_at IS NOT NULL
           GROUP BY day ORDER BY day DESC LIMIT 60""", (survey_id,))
    quiz = None
    survey_row = db.q1(conn, "SELECT quiz_mode FROM surveys WHERE id=?", (survey_id,))
    if survey_row and survey_row["quiz_mode"]:
        agg = db.q1(conn,
            """SELECT AVG(score) avg_score, MIN(score) min_score, MAX(score) max_score,
                      COUNT(score) n FROM responses WHERE survey_id=? AND score IS NOT NULL""",
            (survey_id,))
        quiz = agg
    return {
        "submitted": counts["submitted"], "drafts": counts["drafts"] or 0,
        "questions": stats,
        "timeline": list(reversed(timeline)),
        "quiz": quiz,
    }


# ---------------------------------------------------------------------------
# Summary analytics lives under /summary/* and exports under /export/* —
# these routes MUST be registered before the "/{response_id}" catch pattern.
# FastAPI matches in declaration order, so we declare them above where the
# path-parameter route appears in this module by using separate routers.
# ---------------------------------------------------------------------------


def _question_stats(q: dict, cfg: dict, values: list) -> dict[str, Any]:
    t = q["type"]
    out: dict[str, Any] = {"id": q["id"], "type": t, "title": q["title"], "n": len(values)}
    display_types = {"section", "page_break", "image", "video"}
    if t in display_types:
        out["kind"] = "display"
        return out
    if t in ("short_text", "long_text", "email", "url", "phone"):
        texts = [str(v) for v in values if isinstance(v, (str, int, float))]
        out["kind"] = "text"
        out["items"] = texts[:200]                       # capped list keeps RAM tiny
        words = Counter(w.lower() for text in texts for w in _words(text))
        out["wordcloud"] = [{"word": w, "count": c} for w, c in words.most_common(60)]
        return out
    if t in ("number", "slider", "linear_scale", "rating"):
        nums = [float(v) for v in values if isinstance(v, (int, float))]
        out["kind"] = "numeric"
        if nums:
            srt = sorted(nums)
            n = len(srt)
            median = srt[n // 2] if n % 2 else (srt[n // 2 - 1] + srt[n // 2]) / 2
            cnt = Counter(round(x, 6) for x in nums)
            mode_val, mode_n = cnt.most_common(1)[0]
            bins = _histogram_bins(cfg, nums)
            out.update({"mean": round(sum(nums) / n, 3), "median": round(median, 3),
                        "mode": mode_val, "mode_count": mode_n,
                        "min": srt[0], "max": srt[-1], "count": n,
                        "histogram": bins})
        return out
    if t in ("choice_single", "dropdown", "yes_no"):
        choices = _choice_labels(cfg)
        cnt = Counter(str(v) for v in values if not isinstance(v, list))
        other = sum(1 for v in values if isinstance(v, str) and v.startswith("other:"))
        out["kind"] = "categorical"
        out["distribution"] = [{"label": _label_for(c, choices), "value": c,
                                "count": cnt.get(str(c), 0)} for c in choices]
        if cfg.get("allow_other"):
            out["distribution"].append({"label": "Other", "value": "other", "count": other})
        return out
    if t in ("choice_multi", "ranking"):
        choices = _choice_labels(cfg)
        cnt: Counter = Counter()
        rank_pos: dict[str, list[int]] = {}
        for v in values:
            if isinstance(v, list):
                for i, item in enumerate(v):
                    cnt[str(item)] += 1
                    if t == "ranking":
                        rank_pos.setdefault(str(item), []).append(i)
        out["kind"] = "categorical"
        out["distribution"] = [{"label": _label_for(c, choices), "value": c, "count": cnt.get(str(c), 0)}
                               for c in choices]
        if t == "ranking":
            out["avg_position"] = {k: round(sum(p) / len(p), 2) for k, p in rank_pos.items()}
        return out
    if t in ("grid_single", "matrix"):
        rows, cols = [str(r) for r in cfg.get("rows", [])], [str(c) for c in cfg.get("cols", [])]
        cell: Counter = Counter()
        for v in values:
            if isinstance(v, dict):
                for r, c in v.items():
                    cs = c if isinstance(c, list) else [c]
                    for x in cs:
                        cell[(str(r), str(x))] += 1
        out["kind"] = "grid"
        out["rows"], out["cols"] = rows, cols
        out["cells"] = [{"row": r, "col": c, "count": cell.get((r, c), 0)}
                        for r in rows for c in cols]
        return out
    if t == "grid_multi":
        rows, cols = [str(r) for r in cfg.get("rows", [])], [str(c) for c in cfg.get("cols", [])]
        cell = Counter()
        for v in values:
            if isinstance(v, dict):
                for r, cs in v.items():
                    for x in (cs if isinstance(cs, list) else [cs]):
                        cell[(str(r), str(x))] += 1
        out["kind"] = "grid"
        out["rows"], out["cols"] = rows, cols
        out["cells"] = [{"row": r, "col": c, "count": cell.get((r, c), 0)}
                        for r in rows for c in cols]
        return out
    if t == "file":
        names = [v.get("name", "") for v in values if isinstance(v, dict)]
        multi = [x for v in values if isinstance(v, list) for x in v if isinstance(x, dict)]
        names += [m.get("name", "") for m in multi]
        out["kind"] = "files"
        out["items"] = names[:200]
        return out
    out["kind"] = "raw"
    out["items"] = values[:200]
    return out


def _words(text: str) -> list[str]:
    import re
    return re.findall(r"\w{3,}", text.lower())


def _choice_labels(cfg: dict) -> list[str]:
    labels: list[str] = []
    for c in cfg.get("choices", []):
        labels.append(str(c.get("value", c)) if isinstance(c, dict) else str(c))
    return labels


def _label_for(value: str, choices_cfg: list) -> str:
    return str(value)


def _histogram_bins(cfg: dict, nums: list[float]) -> list[dict]:
    lo, hi = min(nums), max(nums)
    if t_min := cfg.get("min"):
        lo = min(lo, float(t_min))
    if t_max := cfg.get("max"):
        hi = max(hi, float(t_max))
    nbins = 10
    if hi == lo:
        return [{"bin": lo, "count": len(nums)}]
    width = (hi - lo) / nbins
    buckets = [0] * nbins
    for x in nums:
        idx = min(int((x - lo) / width), nbins - 1)
        buckets[idx] += 1
    return [{"bin": round(lo + (i + 0.5) * width, 3), "count": buckets[i]} for i in range(nbins)]


# ---------------------------------------------------------------------------
# Exports — streamed generators (constant memory regardless of response count)
# ---------------------------------------------------------------------------
@static_router.get("/export/csv")
def export_csv(survey_id: int, request: Request, conn=Depends(db.get_db)):
    """Streamed CSV export.

    NOTE: the request-scoped `conn` is closed by FastAPI as soon as this
    handler returns — but StreamingResponse bodies are consumed *after* that.
    So the generator opens its OWN short-lived connection and closes it when
    the stream ends (constant ~4 MB page cache per concurrent download).
    """
    _require_results(conn, survey_id, request)
    questions = db.q(conn, "SELECT id,type,title FROM questions WHERE survey_id=? ORDER BY ordr", (survey_id,))

    def stream() -> Iterator[str]:
        sconn = db._connect(config.DB_PATH)
        try:
            buf = io.StringIO()
            w = csv.writer(buf)
            header = ["response_id", "started_at", "submitted_at", "user_email", "score"]
            w.writerow(header + [f"Q{i+1} {q['title']}" for i, q in enumerate(questions)])
            yield _drain(buf)
            # Cursor over responses, then a small indexed lookup per chunk.
            cur = sconn.execute(
                """SELECT r.id, r.started_at, r.submitted_at, u.email, r.score
                   FROM responses r LEFT JOIN users u ON u.id=r.user_id
                   WHERE r.survey_id=? AND r.submitted_at IS NOT NULL ORDER BY r.id""",
                (survey_id,))
            qids = [q["id"] for q in questions]
            marks = ",".join("?" * len(qids))
            while True:
                chunk = cur.fetchmany(50)                    # bounded fetch size
                if not chunk:
                    break
                ids = [row[0] for row in chunk]
                imarks = ",".join("?" * len(ids))
                amap: dict[int, dict[int, Any]] = {i: {} for i in ids}
                for rid, qid, vj in sconn.execute(
                        f"SELECT response_id,question_id,value_json FROM answers WHERE response_id IN ({imarks})"
                        + (f" AND question_id IN ({marks})" if qids else ""),
                        (*ids, *qids) if qids else ids):
                    amap[rid][qid] = json.loads(vj)
                for row in chunk:
                    vals = [_csv_cell(amap[row[0]].get(qid)) for qid in qids]
                    w.writerow(list(row) + vals)
                yield _drain(buf)
        finally:
            sconn.close()

    fname = f"lunaquest-{survey_id}.csv"
    return StreamingResponse(stream(), media_type="text/csv; charset=utf-8",
                             headers={"content-disposition": f'attachment; filename="{fname}"',
                                      "x-accel-buffering": "no"})



def _drain(buf: io.StringIO) -> str:
    data = buf.getvalue()
    buf.seek(0)
    buf.truncate(0)
    return data


def _csv_cell(val: Any) -> str:
    if val is None:
        return ""
    if isinstance(val, dict):
        if "url" in val and "name" in val:            # file answer
            return f"{val.get('name')} ({val.get('url')})"
        return "; ".join(f"{k}={','.join(map(str, v)) if isinstance(v, list) else v}"
                         for k, v in val.items())
    if isinstance(val, list):
        return " | ".join(str(x) for x in val)
    return str(val)


@static_router.get("/export/json")
def export_json(survey_id: int, request: Request, conn=Depends(db.get_db)):
    """Streamed JSON export (single object with a responses array).

    Uses its own short-lived connection inside the generator — same reason as
    the CSV export above (request-scoped conn is closed before streaming).
    """
    _require_results(conn, survey_id, request)

    def stream() -> Iterator[str]:
        sconn = db._connect(config.DB_PATH)
        try:
            yield '{"responses": ['
            first = True
            cur = sconn.execute(
                """SELECT r.* FROM responses r WHERE r.survey_id=? AND r.submitted_at IS NOT NULL ORDER BY r.id""",
                (survey_id,))
            while True:
                chunk = [dict(r) for r in cur.fetchmany(50)]   # bounded fetch size
                if not chunk:
                    break
                ids = [row["id"] for row in chunk]
                imarks = ",".join("?" * len(ids))
                amap: dict[int, list] = {r["id"]: [] for r in chunk}
                for rid, qid, vj in sconn.execute(
                        f"SELECT response_id,question_id,value_json FROM answers WHERE response_id IN ({imarks})",
                        ids):
                    amap[rid].append({"question_id": qid, "value": json.loads(vj)})
                for row in chunk:
                    row["answers"] = amap[row["id"]]
                    if not first:
                        yield ","
                    first = False
                    yield json.dumps(row, separators=(",", ":"))
            yield "]}"
        finally:
            sconn.close()

    return StreamingResponse(stream(), media_type="application/json",
                             headers={"x-accel-buffering": "no"})
