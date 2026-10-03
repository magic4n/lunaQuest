-- lunaQuest migration 001 — initial schema.
-- Applied by app/db.py in order; each file runs once inside a transaction.
-- Memory notes: WAL mode set at connection time (PRAGMA), FKs enforced,
-- covering indexes on every foreign key and hot lookup path.

CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    email         TEXT NOT NULL UNIQUE COLLATE NOCASE,
    password_hash TEXT NOT NULL,
    name          TEXT NOT NULL DEFAULT '',
    avatar_url    TEXT NOT NULL DEFAULT '',
    role          TEXT NOT NULL DEFAULT 'user' CHECK (role IN ('user','admin')),
    verified      INTEGER NOT NULL DEFAULT 1,       -- email verification flag (off by default)
    banned        INTEGER NOT NULL DEFAULT 0,
    created_at    TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS surveys (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    owner_id      INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    slug          TEXT NOT NULL UNIQUE,
    title         TEXT NOT NULL,
    description   TEXT NOT NULL DEFAULT '',
    cover_image   TEXT NOT NULL DEFAULT '',         -- URL or /api/uploads/... path
    logo          TEXT NOT NULL DEFAULT '',
    settings_json TEXT NOT NULL DEFAULT '{}',       -- visibility, dates, limits, msgs...
    theme_json    TEXT NOT NULL DEFAULT '{}',       -- seed color, dark mode override
    quiz_mode     INTEGER NOT NULL DEFAULT 0,       -- scoring enabled
    published     INTEGER NOT NULL DEFAULT 0,
    closed        INTEGER NOT NULL DEFAULT 0,       -- force-closed by owner/admin
    created_at    TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at    TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_surveys_owner ON surveys(owner_id);
CREATE INDEX IF NOT EXISTS idx_surveys_slug  ON surveys(slug);

CREATE TABLE IF NOT EXISTS questions (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    survey_id    INTEGER NOT NULL REFERENCES surveys(id) ON DELETE CASCADE,
    ordr         INTEGER NOT NULL DEFAULT 0,        -- "order" is reserved-ish; keep explicit
    type         TEXT NOT NULL,                     -- short_text ... matrix (25 types)
    title        TEXT NOT NULL DEFAULT '',
    description  TEXT NOT NULL DEFAULT '',
    required     INTEGER NOT NULL DEFAULT 0,
    config_json  TEXT NOT NULL DEFAULT '{}',        -- choices, scale, validation, media...
    logic_json   TEXT NOT NULL DEFAULT '[]',        -- [{action:'skip_to'|'show', target, op, value}]
    points       REAL NOT NULL DEFAULT 0,           -- quiz score weight
    correct_json TEXT NOT NULL DEFAULT 'null'       -- quiz correct answer(s)
);
CREATE INDEX IF NOT EXISTS idx_questions_survey ON questions(survey_id, ordr);

CREATE TABLE IF NOT EXISTS responses (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    survey_id      INTEGER NOT NULL REFERENCES surveys(id) ON DELETE CASCADE,
    user_id        INTEGER REFERENCES users(id) ON DELETE SET NULL,  -- null = anonymous
    started_at     TEXT NOT NULL DEFAULT (datetime('now')),
    submitted_at   TEXT,                             -- null = saved draft ("save & continue")
    ip_hash        TEXT NOT NULL DEFAULT '',         -- privacy-preserving dedupe hash
    user_agent_hash TEXT NOT NULL DEFAULT '',
    score          REAL                              -- computed for quizzes at submit
);
CREATE INDEX IF NOT EXISTS idx_responses_survey ON responses(survey_id, submitted_at);
CREATE INDEX IF NOT EXISTS idx_responses_user   ON responses(user_id);

CREATE TABLE IF NOT EXISTS answers (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    response_id INTEGER NOT NULL REFERENCES responses(id) ON DELETE CASCADE,
    question_id INTEGER NOT NULL REFERENCES questions(id) ON DELETE CASCADE,
    value_json  TEXT NOT NULL DEFAULT 'null'         -- typed payload per question type
);
CREATE INDEX IF NOT EXISTS idx_answers_response ON answers(response_id);
CREATE INDEX IF NOT EXISTS idx_answers_question ON answers(question_id, response_id);

CREATE TABLE IF NOT EXISTS shares (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    survey_id  INTEGER NOT NULL REFERENCES surveys(id) ON DELETE CASCADE,
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    perm       TEXT NOT NULL DEFAULT 'view' CHECK (perm IN ('view','edit','results')),
    UNIQUE (survey_id, user_id)
);
CREATE INDEX IF NOT EXISTS idx_shares_user ON shares(user_id);

CREATE TABLE IF NOT EXISTS api_keys (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    label      TEXT NOT NULL DEFAULT '',
    key_hash   TEXT NOT NULL UNIQUE,                 -- sha256 of the raw key
    prefix     TEXT NOT NULL,                        -- first 8 chars, shown in UI
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    last_used  TEXT
);
CREATE INDEX IF NOT EXISTS idx_apikeys_user ON api_keys(user_id);

CREATE TABLE IF NOT EXISTS tokens (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    purpose    TEXT NOT NULL CHECK (purpose IN ('verify','reset')),
    token_hash TEXT NOT NULL UNIQUE,
    expires_at TEXT NOT NULL,
    used       INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS settings (
    key   TEXT PRIMARY KEY,                           -- admin-editable site settings
    value TEXT NOT NULL
);
