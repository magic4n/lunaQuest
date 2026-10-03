"""End-to-end test of the required flows against a live in-process app.

Covers: register → login → create survey (multiple question types) → publish →
take → responses → CSV export; quiz scoring; conditional logic; API keys;
admin endpoints; uploads; CSRF behavior.  Run from /workspace:
    python backend/tests/test_e2e.py
"""
from __future__ import annotations

import hashlib
import os
import sys
import tempfile

# Isolated data dir + fast bcrypt for tests (production default stays cost 12).
_TMP = tempfile.mkdtemp(prefix="lunaquest-test-")
os.environ["LUNAQ_DATA_DIR"] = _TMP
os.environ["LUNAQ_DB"] = os.path.join(_TMP, "test.sqlite3")
os.environ["LUNAQ_SECRET_KEY"] = "test-secret-key-not-for-production"
os.environ["LUNAQ_BCRYPT_ROUNDS"] = "4"
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from fastapi.testclient import TestClient  # noqa: E402

from app.main import app  # noqa: E402

PASS = FAIL = 0


def check(name: str, cond: bool, extra: str = "") -> None:
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  OK {name}")
    else:
        FAIL += 1
        print(f"  FAIL {name}  {extra}")


def csrf(client: TestClient) -> dict:
    tok = client.cookies.get("lq_csrf", "")
    return {"X-CSRF-Token": tok} if tok else {}


def main() -> None:
    with TestClient(app) as c:
        r = c.get("/api/site-info")
        check("site-info public", r.status_code == 200 and r.json()["site_name"] == "lunaQuest", r.text)

        r = c.post("/api/auth/register", json={"email": "alice@example.com",
                                               "password": "hunter2abc", "name": "Alice"})
        check("register alice (becomes admin)", r.status_code == 201 and r.json()["user"]["role"] == "admin", r.text)
        check("session cookie set", "lq_session" in c.cookies and bool(c.cookies.get("lq_csrf")))

        r = c.post("/api/auth/register", json={"email": "x@y.zz", "password": "short"}, headers=csrf(c))
        check("weak password rejected 422", r.status_code == 422, r.text)
        r = c.post("/api/auth/register", json={"email": "alice@example.com", "password": "passw0rd1"}, headers=csrf(c))
        check("duplicate email rejected 409", r.status_code == 409, r.text)

        c2 = TestClient(app)
        r = c2.post("/api/auth/register", json={"email": "bob@example.com", "password": "bobpass123", "name": "Bob"})
        check("register bob (user role)", r.status_code == 201 and r.json()["user"]["role"] == "user", r.text)

        c3 = TestClient(app)
        r = c3.post("/api/auth/login", json={"email": "alice@example.com", "password": "wrongpass1"})
        check("bad login 401", r.status_code == 401, r.text)
        r = c3.post("/api/auth/login", json={"email": "alice@example.com", "password": "hunter2abc"})
        check("good login 200", r.status_code == 200, r.text)

        r = c3.post("/api/surveys", json={"title": "no-csrf"})
        check("CSRF blocks mutation without token", r.status_code == 403, r.text)

        payload = {
            "title": "Team Pulse Q4", "description": "Quarterly check-in",
            "slug": "team-pulse-q4", "quiz_mode": False,
            "theme": {"seed": "#6750A4", "mode": "system"},
            "settings": {"visibility": "public", "show_progress": True,
                         "one_per_user": True, "save_later": True,
                         "confirmation_message": "Thanks! Your feedback counts."},
            "questions": [
                {"type": "section", "title": "Intro", "description": "Welcome!"},
                {"type": "short_text", "title": "Your name", "required": True,
                 "config": {"placeholder": "Jane Doe", "max_length": 40}},
                {"type": "choice_single", "title": "Department", "required": True,
                 "config": {"choices": ["Eng", "Design", "Sales"], "allow_other": True}},
                {"type": "linear_scale", "title": "Workload", "required": True,
                 "config": {"min": 1, "max": 10, "min_label": "Light", "max_label": "Heavy"}},
                {"type": "rating", "title": "Satisfaction", "config": {"icon": "stars", "max": 5}},
                {"type": "long_text", "title": "Comments", "config": {"placeholder": "Anything else?"}},
                {"type": "yes_no", "title": "Would you recommend us?", "required": True},
                {"type": "page_break", "title": ""},
                {"type": "number", "title": "Years at company", "config": {"min": 0, "max": 50}},
            ],
        }
        r = c.post("/api/surveys", json=payload, headers=csrf(c))
        check("create survey", r.status_code == 201, r.text)
        survey = r.json()
        sid, slug = survey["id"], survey["slug"]
        qids = [q["id"] for q in survey["questions"]]
        check("survey has 9 questions", len(survey["questions"]) == 9)
        check("custom slug honored", slug == "team-pulse-q4", slug)

        bad = dict(payload, title="Bad", slug="bad-one",
                   questions=[{"type": "choice_single", "title": "x", "config": {"choices": ["only"]}}])
        r = c.post("/api/surveys", json=bad, headers=csrf(c))
        check("choice w/ <2 options rejected 422", r.status_code == 422, r.text)

        r = c.post(f"/api/surveys/{sid}/publish", json={"published": True}, headers=csrf(c))
        check("publish", r.status_code == 200 and r.json()["published"], r.text)

        t = TestClient(app)
        r = t.get(f"/api/public/surveys/{slug}")
        check("public fetch by slug", r.status_code == 200, r.text)
        pub = r.json()
        check("taker payload hides quiz answers", all("correct" not in q for q in pub["questions"]))
        answers = [
            {"question_id": qids[1], "value": "Jane"},
            {"question_id": qids[2], "value": "Eng"},
            {"question_id": qids[3], "value": 7},
            {"question_id": qids[4], "value": 4},
            {"question_id": qids[5], "value": "Great tooling"},
            {"question_id": qids[6], "value": "yes"},
            {"question_id": qids[8], "value": 3},
        ]
        r = t.post(f"/api/public/surveys/{slug}/submit", json={"answers": answers, "submit": True})
        check("anonymous submit ok", r.status_code == 200 and r.json()["submitted"], r.text)

        r = t.post(f"/api/public/surveys/{slug}/submit",
                   json={"answers": [{"question_id": qids[1], "value": "OnlyName"}], "submit": True})
        check("missing required rejected 422", r.status_code == 422, r.text)

        r = t.post(f"/api/public/surveys/{slug}/submit", json={"answers": answers, "submit": True})
        check("one-per-IP dedupe 409", r.status_code == 409, r.text)

        t2 = TestClient(app)
        bad_ans = [dict(a) for a in answers]
        bad_ans[1]["value"] = "NonexistentDept"
        r = t2.post(f"/api/public/surveys/{slug}/submit", json={"answers": bad_ans, "submit": True})
        check("invalid option rejected 422", r.status_code == 422, r.text)

        r = c.get(f"/api/surveys/{sid}/responses")
        check("responses list paginated", r.status_code == 200 and r.json()["total"] >= 1, r.text)
        rid = r.json()["items"][0]["id"]
        r = c.get(f"/api/surveys/{sid}/responses/{rid}")
        check("single response view", r.status_code == 200 and len(r.json()["answers"]) == 7, r.text)
        r = c.get(f"/api/surveys/{sid}/responses/summary/stats")
        stats = r.json()
        kinds = {q["kind"] for q in stats["questions"]}
        check("summary aggregates", r.status_code == 200 and "categorical" in kinds and "numeric" in kinds, r.text)
        num_stats = next(q for q in stats["questions"] if q["type"] == "linear_scale")
        check("mean computed", num_stats.get("mean") == 7.0, str(num_stats))
        r = c.get(f"/api/surveys/{sid}/status")
        check("poll status endpoint", r.status_code == 200 and r.json()["response_count"] >= 1, r.text)

        r = c.get(f"/api/surveys/{sid}/responses/export/csv")
        lines = [ln for ln in r.text.splitlines() if ln.strip()]
        check("CSV export streams", r.status_code == 200 and len(lines) >= 2 and "Jane" in r.text, r.text[:200])
        r = c.get(f"/api/surveys/{sid}/responses/export/json")
        check("JSON export valid", r.status_code == 200 and isinstance(r.json()["responses"], list), r.text[:200])

        r = c.post(f"/api/surveys/{sid}/shares", json={"email": "bob@example.com", "perm": "results"}, headers=csrf(c))
        check("share to bob results", r.status_code == 201, r.text)
        rb = TestClient(app)
        rb.post("/api/auth/login", json={"email": "bob@example.com", "password": "bobpass123"})
        r = rb.get(f"/api/surveys/{sid}/responses")
        check("bob sees results", r.status_code == 200, r.text)
        r = rb.put(f"/api/surveys/{sid}", json=payload, headers=csrf(rb))
        check("bob cannot edit", r.status_code == 403, r.text)

        r = c.post(f"/api/surveys/{sid}/duplicate", headers=csrf(c))
        check("duplicate survey", r.status_code == 201 and len(r.json()["questions"]) == 9, r.text)
        dup_id = r.json()["id"]
        r = c.delete(f"/api/surveys/{dup_id}", headers=csrf(c))
        check("delete duplicate", r.status_code == 200, r.text)

        r = c.get("/api/templates")
        ids = [i["id"] for i in r.json()["items"]]
        check("templates gallery lists", "quiz" in ids and "rsvp" in ids, str(ids))
        r = c.get("/api/templates/quiz")
        check("template fetch with points/correct",
              r.status_code == 200 and r.json()["questions"][0]["points"] == 1, r.text)

        quiz_payload = {
            "title": "Geo Quiz", "slug": "geo-quiz", "quiz_mode": True,
            "settings": {"quiz_show_correct": True},
            "questions": [
                {"type": "choice_single", "title": "Capital of France?", "required": True,
                 "config": {"choices": ["Paris", "Lyon", "Nice"]}, "correct": "Paris", "points": 2},
                {"type": "choice_multi", "title": "Pick seas", "required": True,
                 "config": {"choices": ["Caspian", "Black", "Red"]},
                 "correct": ["Black", "Caspian"], "points": 3},
                {"type": "number", "title": "Rivers guess", "required": True,
                 "config": {"min": 0, "max": 20}, "correct": 10, "points": 1},
            ],
        }
        r = c.post("/api/surveys", json=quiz_payload, headers=csrf(c))
        check("create quiz", r.status_code == 201, r.text)
        qs = r.json()
        qz = [q["id"] for q in qs["questions"]]
        c.post(f"/api/surveys/{qs['id']}/publish", json={"published": True}, headers=csrf(c))
        tq = TestClient(app)
        r = tq.post("/api/public/surveys/geo-quiz/submit", json={
            "answers": [{"question_id": qz[0], "value": "Paris"},
                        {"question_id": qz[1], "value": ["Caspian", "Black"]},
                        {"question_id": qz[2], "value": 10}], "submit": True})
        body = r.json()
        check("quiz perfect score 6/6",
              r.status_code == 200 and body.get("score") == 6 and body.get("max_score") == 6, str(body))
        check("quiz feedback per question",
              len(body.get("feedback", [])) == 3 and all(f["correct"] for f in body["feedback"]), str(body))
        tq2 = TestClient(app)
        r = tq2.post("/api/public/surveys/geo-quiz/submit", json={
            "answers": [{"question_id": qz[0], "value": "Lyon"},
                        {"question_id": qz[1], "value": ["Red"]},
                        {"question_id": qz[2], "value": 4}], "submit": True})
        b2 = r.json()
        check("quiz wrong answers score 0", b2.get("score") == 0, str(b2))
        check("quiz feedback marks wrong", any(not f["correct"] for f in b2.get("feedback", [])), str(b2))

        logic_payload = {
            "title": "Skip Survey", "slug": "skip-survey",
            "questions": [
                {"type": "yes_no", "title": "Do you like pizza?", "required": True},
                {"type": "long_text", "title": "Favorite topping?", "required": True,
                 "logic": [{"action": "hide", "op": "eq", "value": "no", "source_ord": 0}]},
                {"type": "slider", "title": "How much?", "required": True,
                 "config": {"min": 0, "max": 10, "step": 2},
                 "logic": [{"action": "skip_to", "op": "eq", "value": "no", "source_ord": 0, "target_ord": 2}]},
                {"type": "short_text", "title": "Any comment?"},
            ],
        }
        r = c.post("/api/surveys", json=logic_payload, headers=csrf(c))
        ls = r.json()
        lq = [q["id"] for q in ls["questions"]]
        c.post(f"/api/surveys/{ls['id']}/publish", json={"published": True}, headers=csrf(c))
        tl = TestClient(app)
        r = tl.post("/api/public/surveys/skip-survey/submit", json={
            "answers": [{"question_id": lq[0], "value": "no"},
                        {"question_id": lq[1], "value": ""}], "submit": True})
        check("logic: hidden required q skipped on submit", r.status_code == 200, r.text)
        r = tl.post("/api/public/surveys/skip-survey/submit", json={
            "answers": [{"question_id": lq[0], "value": "yes"}], "submit": True})
        check("logic: visible required q enforced", r.status_code == 422, r.text)

        up_payload = {"title": "Upload Form", "slug": "upload-form",
                      "questions": [{"type": "file", "title": "Attach proof"}]}
        r = c.post("/api/surveys", json=up_payload, headers=csrf(c))
        uform = r.json()
        uq = uform["questions"][0]["id"]
        c.post(f"/api/surveys/{uform['id']}/publish", json={"published": True}, headers=csrf(c))
        tu = TestClient(app)
        r = tu.post("/api/public/surveys/upload-form/upload",
                    files={"file": ("note.txt", b"hello lunaquest", "text/plain")})
        check("upload accepted", r.status_code == 200 and r.json()["url"].startswith("/api/uploads/"), r.text)
        url = r.json()["url"]
        r = tu.get(url)
        check("uploaded file served", r.status_code == 200 and r.content == b"hello lunaquest", "")
        r = tu.post("/api/public/surveys/upload-form/upload",
                    files={"file": ("evil.exe", b"MZ....", "application/x-msdownload")})
        check("disallowed MIME rejected 415", r.status_code == 415, r.text)
        r = tu.post("/api/public/surveys/upload-form/submit", json={
            "answers": [{"question_id": uq, "value": {"name": "note.txt", "url": url, "size": 15}}],
            "submit": True})
        check("file answer accepted", r.status_code == 200, r.text)

        pw_payload = {"title": "Secret", "slug": "secret-form",
                      "settings": {"password_hash": hashlib.sha256(b"s3cret").hexdigest()},
                      "questions": [{"type": "short_text", "title": "Passphrase", "required": True}]}
        r = c.post("/api/surveys", json=pw_payload, headers=csrf(c))
        c.post(f"/api/surveys/{r.json()['id']}/publish", json={"published": True}, headers=csrf(c))
        tp = TestClient(app)
        r = tp.get("/api/public/surveys/secret-form")
        check("locked survey hides questions", r.status_code == 200 and "questions" not in r.json(), r.text)
        r = tp.post("/api/public/surveys/secret-form/unlock", json={"password": "wrongpw"})
        check("wrong page password 403", r.status_code == 403, r.text)
        r = tp.post("/api/public/surveys/secret-form/unlock", json={"password": "s3cret"})
        check("correct page password unlocks", r.status_code == 200, r.text)
        r = tp.get("/api/public/surveys/secret-form")
        check("unlocked survey shows questions", "questions" in r.json(), r.text)

        td = TestClient(app)
        td.post("/api/auth/login", json={"email": "bob@example.com", "password": "bobpass123"})
        r = td.post(f"/api/public/surveys/{slug}/submit", json={
            "answers": [{"question_id": qids[1], "value": "Bobby"}], "submit": False})
        check("draft saved", r.status_code == 200, r.text)
        r = td.get(f"/api/public/surveys/{slug}/my-draft")
        check("draft retrieved", r.json()["draft"] is not None, r.text)
        r = td.post(f"/api/public/surveys/{slug}/submit", json={"answers": answers, "submit": True})
        check("draft -> final submit", r.status_code == 200 and r.json()["submitted"], r.text)

        r = c.post("/api/me/api-keys", json={"label": "ci"}, headers=csrf(c))
        check("create api key", r.status_code == 201 and r.json()["key"].startswith("lqk_"), r.text)
        raw_key = r.json()["key"]
        api = TestClient(app)
        r = api.get("/api/surveys", headers={"Authorization": f"Bearer {raw_key}"})
        check("API key authenticates list", r.status_code == 200 and r.json()["total"] >= 1, r.text)
        r = api.get("/api/surveys", headers={"Authorization": "Bearer lqk_bogusbogusbogus"})
        check("bad API key rejected 401", r.status_code == 401, r.text)

        r = c.post("/api/auth/forgot-password", json={"email": "bob@example.com"})
        dev_token = r.json().get("dev_token", "")
        check("forgot returns dev token (no SMTP)", bool(dev_token), r.text)
        r = c.post("/api/auth/reset-password", json={"token": dev_token, "password": "newpass123"})
        check("reset password ok", r.status_code == 200, r.text)
        tc = TestClient(app)
        r = tc.post("/api/auth/login", json={"email": "bob@example.com", "password": "newpass123"})
        check("login with new password", r.status_code == 200, r.text)

        r = c.get("/api/admin/users")
        check("admin lists users", r.status_code == 200 and r.json()["total"] == 2, r.text)
        r = c.get("/api/admin/stats")
        check("admin disk stats", r.status_code == 200 and r.json()["disk"]["db_bytes"] > 0, r.text)
        r = c.put("/api/admin/settings", json={"site_name": "MyPolls", "registration_open": False,
                  "require_email_verification": False, "smtp_host": "", "smtp_port": 587,
                  "smtp_user": "", "smtp_pass": "", "smtp_from": "", "session_hours": 48,
                  "max_upload_mb": 10}, headers=csrf(c))
        check("admin update settings", r.status_code == 200, r.text)
        r2 = TestClient(app)
        r = r2.get("/api/site-info")
        check("site-info reflects settings",
              r.json()["site_name"] == "MyPolls" and not r.json()["registration_open"], r.text)
        r = r2.post("/api/auth/register", json={"email": "eve@e.com", "password": "passwor1d"})
        check("closed registration rejects signup", r.status_code == 403, r.text)
        r = c.get("/api/admin/surveys")
        check("admin lists all surveys", r.status_code == 200 and r.json()["total"] >= 4, r.text)
        r = c.post(f"/api/admin/surveys/{sid}/force-close", headers=csrf(c))
        check("admin force close", r.status_code == 200, r.text)
        r = TestClient(app).get(f"/api/public/surveys/{slug}")
        check("closed survey 410", r.status_code == 410, r.text)
        r = c.get("/api/admin/backup")
        check("backup requires POST", r.status_code == 405, r.text)
        r = c.post("/api/admin/backup", headers=csrf(c))
        check("backup downloads sqlite", r.status_code == 200 and len(r.content) > 4096, "")
        r = rb.get("/api/admin/users")
        check("non-admin blocked from admin", r.status_code == 403, r.text)

        r = c.get(f"/api/surveys/{sid}/responses?limit=500")
        check("limit capped at 100 -> 422", r.status_code == 422, r.text)

        r = c.post("/api/auth/logout", headers=csrf(c))
        check("logout clears cookies", r.status_code == 200, r.text)
        r = c.get("/api/auth/me")
        check("me after logout null", r.json()["user"] is None, r.text)

    print(f"\nRESULT: {PASS} passed, {FAIL} failed")
    if FAIL:
        sys.exit(1)


if __name__ == "__main__":
    main()
