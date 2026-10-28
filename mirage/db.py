"""SQLite storage: personas, sessions, events (the logging schema), cached artifacts,
and the tables the analyst agent will write to later (analysis_runs/findings/proposed_rules).

Everything here is synchronous; callers use asyncio.to_thread(...) from async code.
"""
from __future__ import annotations

import json
import sqlite3
import threading
import time
from typing import Any

SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA synchronous=NORMAL;

CREATE TABLE IF NOT EXISTS personas (
    id          TEXT PRIMARY KEY,
    created_at  REAL NOT NULL,
    active      INTEGER NOT NULL DEFAULT 0,
    spec_json   TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
    id             TEXT PRIMARY KEY,
    persona_id     TEXT NOT NULL,
    mode           TEXT NOT NULL,          -- 'mirage' | 'static' (A/B comparison)
    src_ip         TEXT,
    user_agent     TEXT,
    first_seen     REAL NOT NULL,
    last_seen      REAL NOT NULL,
    request_count  INTEGER NOT NULL DEFAULT 0,
    llm_calls      INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_sessions_last_seen ON sessions(last_seen);

CREATE TABLE IF NOT EXISTS events (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    request_id        TEXT NOT NULL,
    session_id        TEXT NOT NULL,
    persona_id        TEXT NOT NULL,
    mode              TEXT NOT NULL,
    ts                REAL NOT NULL,
    src_ip            TEXT,
    method            TEXT,
    path              TEXT,
    query             TEXT,
    headers_json      TEXT,
    body              TEXT,
    body_truncated    INTEGER NOT NULL DEFAULT 0,
    status            INTEGER,
    content_type      TEXT,
    response_bytes    INTEGER,
    response_source   TEXT,   -- cache | generated | coalesced | fallback | budget | static
    latency_ms        INTEGER,
    llm_model         TEXT,
    llm_ms            INTEGER,
    prompt_tokens     INTEGER,
    completion_tokens INTEGER
);
CREATE INDEX IF NOT EXISTS idx_events_session_ts ON events(session_id, ts);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);

CREATE TABLE IF NOT EXISTS artifacts (
    persona_id    TEXT NOT NULL,
    cache_key     TEXT NOT NULL,
    status        INTEGER NOT NULL,
    content_type  TEXT NOT NULL,
    body          TEXT NOT NULL,
    created_at    REAL NOT NULL,
    hits          INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (persona_id, cache_key)
);

-- Analyst agent output (populated by the offline analysis job, day 4+)
CREATE TABLE IF NOT EXISTS analysis_runs (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at     REAL NOT NULL,
    finished_at    REAL,
    model          TEXT,
    session_count  INTEGER,
    notes          TEXT
);

CREATE TABLE IF NOT EXISTS findings (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id            INTEGER NOT NULL,
    session_id        TEXT NOT NULL,
    intent            TEXT,           -- recon | cred_stuffing | injection | ...
    attack_technique  TEXT,           -- MITRE ATT&CK id, e.g. T1190
    confidence        REAL,
    summary           TEXT,
    evidence_json     TEXT,
    cves_json         TEXT,           -- Tavily-enriched
    created_at        REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS proposed_rules (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id        INTEGER NOT NULL,
    finding_id    INTEGER,
    kind          TEXT NOT NULL,      -- nginx | modsecurity | sigma
    rule_text     TEXT NOT NULL,
    replay_total  INTEGER,            -- events replayed against the rule
    true_pos      INTEGER,
    false_pos     INTEGER,
    status        TEXT NOT NULL DEFAULT 'proposed',
    created_at    REAL NOT NULL
);

-- Headline metric for the static-vs-Mirage comparison
CREATE VIEW IF NOT EXISTS session_stats AS
SELECT s.id AS session_id, s.mode, s.src_ip, s.user_agent, s.first_seen, s.last_seen,
       s.last_seen - s.first_seen AS duration_s,
       s.request_count, s.llm_calls,
       (SELECT COUNT(DISTINCT e.path) FROM events e WHERE e.session_id = s.id) AS distinct_paths
FROM sessions s;
"""


class Database:
    def __init__(self, path: str = "mirage.db"):
        self._conn = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        self._conn.row_factory = sqlite3.Row
        self._lock = threading.RLock()
        with self._lock:
            self._conn.executescript(SCHEMA)

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    # ---- helpers ----
    def _run(self, sql: str, params: tuple = ()) -> None:
        with self._lock:
            self._conn.execute(sql, params)

    def _one(self, sql: str, params: tuple = ()) -> sqlite3.Row | None:
        with self._lock:
            return self._conn.execute(sql, params).fetchone()

    def _all(self, sql: str, params: tuple = ()) -> list[sqlite3.Row]:
        with self._lock:
            return self._conn.execute(sql, params).fetchall()

    # ---- personas ----
    def save_persona(self, persona_id: str, spec: dict[str, Any], *, make_active: bool = True) -> None:
        with self._lock:
            if make_active:
                self._conn.execute("UPDATE personas SET active = 0")
            self._conn.execute(
                "INSERT OR REPLACE INTO personas (id, created_at, active, spec_json) VALUES (?,?,?,?)",
                (persona_id, time.time(), 1 if make_active else 0, json.dumps(spec)),
            )

    def get_active_persona(self) -> dict[str, Any] | None:
        row = self._one("SELECT id, spec_json FROM personas WHERE active = 1 ORDER BY created_at DESC LIMIT 1")
        if not row:
            return None
        spec = json.loads(row["spec_json"])
        spec["persona_id"] = row["id"]
        return spec

    # ---- sessions ----
    def touch_session(self, sid: str, persona_id: str, mode: str, ip: str, ua: str) -> None:
        now = time.time()
        with self._lock:
            self._conn.execute(
                "INSERT OR IGNORE INTO sessions (id, persona_id, mode, src_ip, user_agent, first_seen, last_seen) "
                "VALUES (?,?,?,?,?,?,?)",
                (sid, persona_id, mode, ip, ua, now, now),
            )
            self._conn.execute(
                "UPDATE sessions SET last_seen = ?, request_count = request_count + 1 WHERE id = ?",
                (now, sid),
            )

    def bump_llm_calls(self, sid: str) -> None:
        self._run("UPDATE sessions SET llm_calls = llm_calls + 1 WHERE id = ?", (sid,))

    def session_llm_calls(self, sid: str) -> int:
        row = self._one("SELECT llm_calls FROM sessions WHERE id = ?", (sid,))
        return int(row["llm_calls"]) if row else 0

    def recent_events(self, sid: str, n: int = 6) -> list[tuple[str, str, int]]:
        rows = self._all(
            "SELECT method, path, status FROM events WHERE session_id = ? ORDER BY id DESC LIMIT ?",
            (sid, n),
        )
        return [(r["method"], r["path"], r["status"]) for r in reversed(rows)]

    # ---- artifacts (response cache = consistency) ----
    def get_artifact(self, persona_id: str, key: str) -> dict[str, Any] | None:
        row = self._one(
            "SELECT status, content_type, body FROM artifacts WHERE persona_id = ? AND cache_key = ?",
            (persona_id, key),
        )
        return dict(row) if row else None

    def put_artifact(self, persona_id: str, key: str, status: int, content_type: str, body: str) -> None:
        self._run(
            "INSERT OR IGNORE INTO artifacts (persona_id, cache_key, status, content_type, body, created_at) "
            "VALUES (?,?,?,?,?,?)",
            (persona_id, key, status, content_type, body, time.time()),
        )

    def hit_artifact(self, persona_id: str, key: str) -> None:
        self._run(
            "UPDATE artifacts SET hits = hits + 1 WHERE persona_id = ? AND cache_key = ?",
            (persona_id, key),
        )

    # ---- events ----
    def log_event(self, **e: Any) -> None:
        cols = (
            "request_id", "session_id", "persona_id", "mode", "ts", "src_ip", "method", "path", "query",
            "headers_json", "body", "body_truncated", "status", "content_type", "response_bytes",
            "response_source", "latency_ms", "llm_model", "llm_ms", "prompt_tokens", "completion_tokens",
        )
        vals = tuple(e.get(c) for c in cols)
        self._run(
            f"INSERT INTO events ({', '.join(cols)}) VALUES ({', '.join('?' for _ in cols)})",
            vals,
        )

    def events_for_session(self, sid: str) -> list[dict[str, Any]]:
        return [dict(r) for r in self._all("SELECT * FROM events WHERE session_id = ? ORDER BY id", (sid,))]
