"""The request log: one SQLite row per request the proxy has decided on, plus
the rule proposals an admin reviews.

The database lives at LOG_DB (default logs/chokidaar.db). Request bodies are
never stored, only their SHA-256, so the log does not keep passwords or other
data people send.
"""
import os
import sqlite3
from contextlib import contextmanager
from pathlib import Path

DEFAULT_PATH = os.path.join("logs", "chokidaar.db")
DECISIONS = ("allow", "block", "flagged")
PROPOSAL_STATUSES = ("pending", "approved", "rejected")

SCHEMA = f"""
CREATE TABLE IF NOT EXISTS requests (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    ts        TEXT NOT NULL,
    ip        TEXT,
    method    TEXT NOT NULL,
    path      TEXT NOT NULL,
    query     TEXT NOT NULL DEFAULT '',
    body_hash TEXT NOT NULL,
    decision  TEXT NOT NULL CHECK (decision IN {DECISIONS}),
    rule_id   TEXT,
    ml_score  REAL,
    reason    TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS requests_decision_ip ON requests (decision, ip);

CREATE TABLE IF NOT EXISTS rule_proposals (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    pattern     TEXT NOT NULL,
    attack_type TEXT NOT NULL,
    rationale   TEXT NOT NULL DEFAULT '',
    status      TEXT NOT NULL DEFAULT 'pending'
                CHECK (status IN {PROPOSAL_STATUSES})
);
"""


def path_from_env(environ=None) -> str:
    environ = os.environ if environ is None else environ
    return environ.get("LOG_DB", "").strip() or DEFAULT_PATH


class LogStore:
    """Opens a short-lived connection per call, so one store can be used from
    any thread. The tables are created on first use, not on construction, so a
    proxy whose log location is broken still starts and serves requests."""

    def __init__(self, path: str = None):
        self.path = path or path_from_env()
        self._ready = False

    @contextmanager
    def connect(self):
        """A connection that commits on success and is always closed."""
        if not self._ready:
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(self.path, timeout=5.0)
        try:
            conn.row_factory = sqlite3.Row
            if not self._ready:
                conn.executescript(SCHEMA)
                self._ready = True
            with conn:
                yield conn
        finally:
            conn.close()
