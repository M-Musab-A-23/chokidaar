"""The request log: one SQLite row per request the proxy has decided on, plus
the rule proposals an admin reviews.

The database lives at LOG_DB (default logs/chokidaar.db). Request bodies are
never stored, only their SHA-256, so the log does not keep passwords or other
data people send.
"""
import hashlib
import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone
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

    def add_request(self, *, method: str, path: str, query: str, body: bytes,
                    decision: str, ip: str = None, rule_id: str = None,
                    ml_score: float = None, reason: str = "", ts: str = None) -> int:
        """Store one request and return its id. `body` is hashed here and the
        raw bytes go nowhere else."""
        if decision not in DECISIONS:
            raise ValueError(f"decision must be one of {', '.join(DECISIONS)}, got {decision!r}")
        row = (ts or _now(), ip, method, path, query, body_hash(body),
               decision, rule_id, ml_score, reason)
        with self.connect() as conn:
            cursor = conn.execute(
                "INSERT INTO requests (ts, ip, method, path, query, body_hash, decision,"
                " rule_id, ml_score, reason) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", row)
            return cursor.lastrowid

    def recent(self, limit: int = 50) -> list:
        """The newest requests first, as dicts."""
        with self.connect() as conn:
            rows = conn.execute("SELECT * FROM requests ORDER BY id DESC LIMIT ?",
                                (max(0, int(limit)),))
            return [dict(r) for r in rows]

    def counts(self) -> dict:
        """Number of requests per decision; every decision is present, even at 0."""
        totals = dict.fromkeys(DECISIONS, 0)
        with self.connect() as conn:
            for decision, n in conn.execute(
                    "SELECT decision, COUNT(*) FROM requests GROUP BY decision"):
                totals[decision] = n
        return totals

    def top_blocked_ips(self, limit: int = 10) -> list:
        """[(ip, blocks)] for the IPs with the most blocked requests, most first;
        ties are broken by IP so the order is stable."""
        with self.connect() as conn:
            rows = conn.execute(
                "SELECT ip, COUNT(*) AS blocks FROM requests"
                " WHERE decision = 'block' AND ip IS NOT NULL"
                " GROUP BY ip ORDER BY blocks DESC, ip LIMIT ?", (max(0, int(limit)),))
            return [(r["ip"], r["blocks"]) for r in rows]


def body_hash(body: bytes) -> str:
    return hashlib.sha256(body).hexdigest()


def _now() -> str:
    # UTC ISO 8601 with milliseconds; sorts the same as time.
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")
