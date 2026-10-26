"""SQLite append-only audit store (M6, D5).

ENFORCED AT APP LAYER: this module exposes INSERT and SELECT only — no
UPDATE or DELETE code path exists anywhere (test-asserted by source scan
and by rows-monotonic behavior). Every row carries an ISO-8601 UTC
timestamp plus a ``case_id`` correlation key (meta included, nullable).
G7 verbatim prompt/response pairs persist here byte-exact with their
sha256 digest — not just in logs (P6).

Schema versioning: a ``schema_version`` meta row is written at creation
so future migrations have an anchor.
"""
from __future__ import annotations

import json
import re
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SCHEMA_VERSION = "m6"

_DDL = """
CREATE TABLE IF NOT EXISTS meta (
    key      TEXT PRIMARY KEY,
    value    TEXT NOT NULL,
    ts       TEXT NOT NULL,
    case_id  TEXT
);
CREATE TABLE IF NOT EXISTS decisions (
    id             INTEGER PRIMARY KEY AUTOINCREMENT,
    ts             TEXT NOT NULL,
    case_id        TEXT NOT NULL,
    incident_id    TEXT NOT NULL,
    outcome        TEXT NOT NULL,
    score          REAL NOT NULL,
    base_score     REAL NOT NULL,
    tier           TEXT NOT NULL,
    cap_applied    TEXT,
    would          TEXT NOT NULL DEFAULT '',
    recommendation TEXT NOT NULL DEFAULT '{}',
    audit_events   TEXT NOT NULL DEFAULT '[]'
);
CREATE TABLE IF NOT EXISTS llm_pairs (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    ts                TEXT NOT NULL,
    case_id           TEXT NOT NULL,
    prompt_verbatim   TEXT NOT NULL,
    response_verbatim TEXT NOT NULL,
    status            TEXT NOT NULL,
    elapsed_ms        INTEGER NOT NULL,
    digest            TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS actions (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts          TEXT NOT NULL,
    case_id     TEXT NOT NULL,
    action_type TEXT NOT NULL,
    target_ip   TEXT,
    ttl_minutes INTEGER,
    verdict     TEXT NOT NULL,
    executed    INTEGER NOT NULL DEFAULT 0,
    detail      TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS rollbacks (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    ts       TEXT NOT NULL,
    case_id  TEXT NOT NULL,
    token    TEXT NOT NULL,
    ok       INTEGER NOT NULL,
    detail   TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS kpis_events (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    ts      TEXT NOT NULL,
    case_id TEXT NOT NULL,
    name    TEXT NOT NULL,
    value   REAL NOT NULL,
    detail  TEXT NOT NULL DEFAULT ''
);
"""

#: Append-only enforcement (M6): UPDATE/DELETE raise immediately at the
#: SQLite layer on every audit table — immutability is enforced by the
#: store file itself, not by caller discipline.
_IMMUTABLE_TABLES = ("meta", "decisions", "llm_pairs", "actions",
                     "rollbacks", "kpis_events")


def _immutability_ddl() -> str:
    stmts = []
    for t in _IMMUTABLE_TABLES:
        for op in ("UPDATE", "DELETE"):
            stmts.append(
                f"CREATE TRIGGER IF NOT EXISTS {t}_no_{op.lower()} "
                f"BEFORE {op} ON {t} FOR EACH ROW BEGIN "
                f"SELECT RAISE(ABORT, '{t} is append-only: {op} forbidden'); "
                f"END;"
            )
    return "\n".join(stmts) + "\n"



_TABLE_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def _check_table(table: str) -> None:
    if not _TABLE_RE.fullmatch(table):
        raise ValueError(f"table must be a bare identifier: {table!r}")


def _utc_now_iso() -> str:
    return datetime.now(tz=timezone.utc).isoformat()


class Store:
    """Append-only audit store handle. One file, single-writer discipline;
    concurrent writers are out of M6 scope (documented limitation).
    """

    def __init__(self, path: str | Path,
                 check_same_thread: bool = True) -> None:
        self._path = Path(path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        # M7: the Ops UI serves requests from uvicorn worker threads while
        # the embedded engine writes on its own thread; callers that share
        # one Store across threads opt in with check_same_thread=False
        # (SQLite's internal locking serializes access).
        self._conn = sqlite3.connect(str(self._path),
                                     check_same_thread=check_same_thread)
        self._conn.executescript(_DDL)
        # Append-only triggers — enforced at the SQLite layer.
        self._conn.executescript(_immutability_ddl())
        self._conn.commit()
        self._conn.commit()
        row = self._conn.execute(
            "SELECT value FROM meta WHERE key='schema_version'").fetchone()
        if row is None:
            self.record_meta("schema_version", SCHEMA_VERSION)

    # -- INSERT surface (the ONLY mutation paths) ----------------------- #

    def record_meta(self, key: str, value: str, *,
                    case_id: str | None = None) -> int:
        cur = self._conn.execute(
            "INSERT INTO meta (key, value, ts, case_id) VALUES (?,?,?,?)",
            (key, value, _utc_now_iso(), case_id))
        self._conn.commit()
        return int(cur.lastrowid)

    def record_decision(self, *, case_id: str, incident_id: str,
                        outcome: str, score: float, base_score: float,
                        tier: str, cap_applied: str | None,
                        would: str, recommendation: dict[str, Any],
                        audit_events: list[dict[str, str]]) -> int:
        cur = self._conn.execute(
            "INSERT INTO decisions (ts, case_id, incident_id, outcome,"
            " score, base_score, tier, cap_applied, would, recommendation,"
            " audit_events)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (_utc_now_iso(), case_id, incident_id, outcome, score,
             base_score, tier, cap_applied, would,
             json.dumps(recommendation, sort_keys=True),
             json.dumps(audit_events, sort_keys=True)))
        self._conn.commit()
        return int(cur.lastrowid)

    def record_llm_pair(self, *, case_id: str, prompt_verbatim: str,
                        response_verbatim: str, status: str,
                        elapsed_ms: int, digest: str) -> int:
        cur = self._conn.execute(
            "INSERT INTO llm_pairs (ts, case_id, prompt_verbatim,"
            " response_verbatim, status, elapsed_ms, digest)"
            " VALUES (?,?,?,?,?,?,?)",
            (_utc_now_iso(), case_id, prompt_verbatim, response_verbatim,
             status, elapsed_ms, digest))
        self._conn.commit()
        return int(cur.lastrowid)

    def record_action(self, *, case_id: str, action_type: str,
                      target_ip: str | None, ttl_minutes: int | None,
                      verdict: str, executed: bool,
                      detail: str = "") -> int:
        cur = self._conn.execute(
            "INSERT INTO actions (ts, case_id, action_type, target_ip,"
            " ttl_minutes, verdict, executed, detail) VALUES (?,?,?,?,?,?,?,?)",
            (_utc_now_iso(), case_id, action_type, target_ip, ttl_minutes,
             verdict, 1 if executed else 0, detail))
        self._conn.commit()
        return int(cur.lastrowid)

    def record_rollback(self, *, case_id: str, token: str, ok: bool,
                        detail: str = "") -> int:
        cur = self._conn.execute(
            "INSERT INTO rollbacks (ts, case_id, token, ok, detail)"
            " VALUES (?,?,?,?,?)",
            (_utc_now_iso(), case_id, token, 1 if ok else 0, detail))
        self._conn.commit()
        return int(cur.lastrowid)

    def record_kpi_event(self, *, case_id: str, name: str, value: float,
                         detail: str = "") -> int:
        cur = self._conn.execute(
            "INSERT INTO kpis_events (ts, case_id, name, value, detail)"
            " VALUES (?,?,?,?,?)",
            (_utc_now_iso(), case_id, name, value, detail))
        self._conn.commit()
        return int(cur.lastrowid)

    # -- SELECT surface (read-only projections for KPIs/summary) -------- #

    def query(self, sql: str, params: tuple = ()) -> list[tuple]:
        """Raw read passthrough — callers use SELECT statements only."""
        if not sql.lstrip().upper().startswith("SELECT"):
            raise ValueError("Store.query accepts SELECT statements only")
        return self._conn.execute(sql, params).fetchall()

    def count(self, table: str) -> int:
        _check_table(table)
        row = self._conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()
        return int(row[0])

    def rows(self, table: str) -> list[dict[str, Any]]:
        _check_table(table)
        cur = self._conn.execute(f"SELECT * FROM {table}")
        cols = [d[0] for d in cur.description]
        return [dict(zip(cols, r)) for r in cur.fetchall()]

    def meta_get(self, key: str) -> str | None:
        row = self._conn.execute(
            "SELECT value FROM meta WHERE key=?", (key,)).fetchone()
        return row[0] if row else None

    def close(self) -> None:
        self._conn.close()
