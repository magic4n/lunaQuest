"""SQLite access layer — stdlib sqlite3, raw SQL, per-request connections.

Memory discipline:
  * One connection per request via a FastAPI `yield` dependency; closed promptly.
  * WAL journal so readers never block the single writer.
  * row_factory = sqlite3.Row for cheap dict-like access without ORM overhead.
  * No global caches. The only long-lived object is the write-serialized pool
    of fresh connections (created on demand, garbage collected after request).
"""
from __future__ import annotations

import hashlib
import re
import sqlite3
from pathlib import Path
from typing import Any, Iterable

from . import config

# ---------------------------------------------------------------------------
# Migrations
# ---------------------------------------------------------------------------
_MIGRATION_RE = re.compile(r"^\d{3}_.+\.sql$")


def _connect(path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(str(path), timeout=15, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")          # concurrent readers, tiny RAM
    conn.execute("PRAGMA foreign_keys=ON")           # enforce FKs
    conn.execute("PRAGMA synchronous=NORMAL")        # safe with WAL
    conn.execute("PRAGMA busy_timeout=15000")
    conn.execute("PRAGMA cache_size=-4000")          # ~4 MB page cache per conn
    return conn


def migrate() -> None:
    """Apply every migrations/*.sql file once, tracked in schema_migrations."""
    config.DATA_DIR.mkdir(parents=True, exist_ok=True)
    config.UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    conn = _connect(config.DB_PATH)
    try:
        conn.execute("CREATE TABLE IF NOT EXISTS schema_migrations (name TEXT PRIMARY KEY)")
        applied = {r["name"] for r in conn.execute("SELECT name FROM schema_migrations")}
        files = sorted(p.name for p in config.MIGRATIONS_DIR.iterdir() if _MIGRATION_RE.match(p.name))
        for fname in files:
            if fname in applied:
                continue
            sql = (config.MIGRATIONS_DIR / fname).read_text(encoding="utf-8")
            conn.execute("BEGIN")
            try:
                # Statement-wise execution keeps the whole migration atomic
                # (executescript would auto-commit mid-file).
                for stmt in _split_statements(sql):
                    conn.execute(stmt)
                conn.execute("INSERT INTO schema_migrations (name) VALUES (?)", (fname,))
                conn.execute("COMMIT")
            except Exception:
                conn.execute("ROLLBACK")
                raise
    finally:
        conn.close()


def _split_statements(sql: str) -> Iterable[str]:
    """Split a migration file into statements, dropping comment-only chunks."""
    out: list[str] = []
    buf: list[str] = []
    for line in sql.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("--"):
            continue
        buf.append(line)
        if stripped.endswith(";"):
            out.append("\n".join(buf))
            buf = []
    if buf:
        out.append("\n".join(buf))
    return out


# ---------------------------------------------------------------------------
# Request-scoped connection (FastAPI dependency with yield)
# ---------------------------------------------------------------------------
def get_db() -> Any:
    """Yield a per-request connection; always closed, even on exceptions."""
    conn = _connect(config.DB_PATH)
    try:
        yield conn
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Tiny query helpers (keep routers readable; all parameterized — no injection)
# ---------------------------------------------------------------------------
def q(conn: sqlite3.Connection, sql: str, params: tuple = ()) -> list[dict]:
    return [dict(r) for r in conn.execute(sql, params).fetchall()]


def q1(conn: sqlite3.Connection, sql: str, params: tuple = ()) -> dict | None:
    row = conn.execute(sql, params).fetchone()
    return dict(row) if row else None


def execute(conn: sqlite3.Connection, sql: str, params: tuple = ()) -> int:
    cur = conn.execute(sql, params)
    return cur.lastrowid if cur.lastrowid else cur.rowcount


def hash_ip(ip: str) -> str:
    """Privacy-preserving response dedupe key (salted with SECRET_KEY)."""
    return hashlib.sha256(f"{config.SECRET_KEY}|{ip}".encode()).hexdigest()[:32]


def hash_ua(ua: str) -> str:
    return hashlib.sha256(f"ua|{ua[:200]}".encode()).hexdigest()[:32]


def backup_to(dest: Path) -> Path:
    """Online SQLite backup via the backup API — safe while serving traffic."""
    src = _connect(config.DB_PATH)
    dst = sqlite3.connect(str(dest))
    try:
        src.backup(dst)
    finally:
        dst.close()
        src.close()
    return dest


def disk_usage() -> dict:
    """DB + uploads footprint for the admin panel (no external deps)."""
    db_bytes = sum(p.stat().st_size for p in config.DATA_DIR.glob("lunaquest.sqlite3*") if p.exists())
    up_bytes = sum(f.stat().st_size for f in config.UPLOAD_DIR.rglob("*") if f.is_file())
    return {"db_bytes": db_bytes, "uploads_bytes": up_bytes,
            "upload_count": sum(1 for f in config.UPLOAD_DIR.rglob("*") if f.is_file())}
