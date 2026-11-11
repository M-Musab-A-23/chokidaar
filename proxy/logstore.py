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

    def recent(self, limit: int = 50, decision: str = None, ip: str = None) -> list:
        """The newest requests first, as dicts, optionally only those with one
        decision and/or from one IP."""
        if decision is not None and decision not in DECISIONS:
            raise ValueError(f"decision must be one of {', '.join(DECISIONS)}, got {decision!r}")
        where, params = [], []
        if decision is not None:
            where.append("decision = ?")
            params.append(decision)
        if ip is not None:
            where.append("ip = ?")
            params.append(ip)
        sql = "SELECT * FROM requests"
        if where:
            sql += " WHERE " + " AND ".join(where)
        sql += " ORDER BY id DESC LIMIT ?"
        params.append(max(0, int(limit)))
        with self.connect() as conn:
            return [dict(r) for r in conn.execute(sql, params)]

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

    def hourly(self, since: datetime) -> dict:
        """{'YYYY-MM-DDTHH': (requests, blocks)} per UTC hour for requests at or
        after `since`; hours without requests are left out."""
        start = since.astimezone(timezone.utc).isoformat(timespec="milliseconds")
        with self.connect() as conn:
            rows = conn.execute(
                "SELECT substr(ts, 1, 13) AS hour, COUNT(*) AS requests,"
                " SUM(decision = 'block') AS blocks FROM requests"
                " WHERE ts >= ? GROUP BY hour ORDER BY hour", (start,))
            return {r["hour"]: (r["requests"], r["blocks"]) for r in rows}

    def blocked_and_flagged(self, limit: int = 200) -> list:
        """The newest blocked or flagged requests first, as dicts."""
        with self.connect() as conn:
            rows = conn.execute(
                "SELECT * FROM requests WHERE decision IN ('block', 'flagged')"
                " ORDER BY id DESC LIMIT ?", (max(0, int(limit)),))
            return [dict(r) for r in rows]

    def add_proposal(self, *, pattern: str, attack_type: str, rationale: str = ""):
        """Store a pending rule proposal and return its id, or None if the same
        pattern was already proposed for the same attack type (whatever its
        status, so a rejected rule is not proposed again)."""
        with self.connect() as conn:
            if conn.execute("SELECT 1 FROM rule_proposals WHERE pattern = ? AND attack_type = ?",
                            (pattern, attack_type)).fetchone():
                return None
            cursor = conn.execute(
                "INSERT INTO rule_proposals (pattern, attack_type, rationale) VALUES (?, ?, ?)",
                (pattern, attack_type, rationale))
            return cursor.lastrowid

    def proposals(self, status: str = None) -> list:
        """Rule proposals in the order they were made, optionally only those
        with one status."""
        if status is not None and status not in PROPOSAL_STATUSES:
            raise ValueError(f"status must be one of {', '.join(PROPOSAL_STATUSES)}, got {status!r}")
        with self.connect() as conn:
            if status is None:
                rows = conn.execute("SELECT * FROM rule_proposals ORDER BY id")
            else:
                rows = conn.execute("SELECT * FROM rule_proposals WHERE status = ? ORDER BY id",
                                    (status,))
            return [dict(r) for r in rows]

    def approve(self, proposal_id: int) -> None:
        """Mark a proposal approved; the proxy loads it as a rule on its next start."""
        self._set_status(proposal_id, "approved")

    def reject(self, proposal_id: int) -> None:
        """Mark a proposal rejected; it is never loaded or proposed again."""
        self._set_status(proposal_id, "rejected")

    def _set_status(self, proposal_id: int, status: str) -> None:
        with self.connect() as conn:
            cursor = conn.execute("UPDATE rule_proposals SET status = ? WHERE id = ?",
                                  (status, int(proposal_id)))
            if cursor.rowcount == 0:
                raise KeyError(f"no rule proposal with id {proposal_id}")


def body_hash(body: bytes) -> str:
    return hashlib.sha256(body).hexdigest()


def _now() -> str:
    # UTC ISO 8601 with milliseconds; sorts the same as time.
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")
