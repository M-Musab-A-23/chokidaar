import os
import sqlite3

import pytest

from proxy.logstore import DEFAULT_PATH, LogStore, path_from_env


@pytest.fixture
def store(tmp_path):
    return LogStore(str(tmp_path / "logs" / "test.db"))


def _columns(store, table):
    with store.connect() as conn:
        return [row["name"] for row in conn.execute(f"PRAGMA table_info({table})")]


def test_path_comes_from_log_db_with_a_default():
    assert path_from_env({"LOG_DB": "/var/lib/chokidaar/log.db"}) == "/var/lib/chokidaar/log.db"
    assert path_from_env({}) == DEFAULT_PATH == os.path.join("logs", "chokidaar.db")
    assert path_from_env({"LOG_DB": "  "}) == DEFAULT_PATH


def test_store_uses_log_db_when_no_path_is_given(monkeypatch, tmp_path):
    monkeypatch.setenv("LOG_DB", str(tmp_path / "from_env.db"))
    assert LogStore().path == str(tmp_path / "from_env.db")


def test_nothing_is_created_until_first_use(store):
    assert not os.path.exists(store.path)


def test_tables_are_created_with_their_columns(store):
    assert _columns(store, "requests") == [
        "id", "ts", "ip", "method", "path", "query", "body_hash",
        "decision", "rule_id", "ml_score", "reason",
    ]
    assert _columns(store, "rule_proposals") == [
        "id", "pattern", "attack_type", "rationale", "status",
    ]
    assert os.path.exists(store.path)


def test_decision_must_be_allow_block_or_flagged(store):
    row = "INSERT INTO requests (ts, method, path, body_hash, decision) VALUES ('t', 'GET', '/', 'h', ?)"
    with store.connect() as conn:
        for decision in ("allow", "block", "flagged"):
            conn.execute(row, (decision,))
    with pytest.raises(sqlite3.IntegrityError), store.connect() as conn:
        conn.execute(row, ("blocked",))


def test_proposals_start_pending_and_status_is_checked(store):
    with store.connect() as conn:
        conn.execute("INSERT INTO rule_proposals (pattern, attack_type) VALUES ('x', 'sqli')")
        assert conn.execute("SELECT status FROM rule_proposals").fetchone()["status"] == "pending"
    with pytest.raises(sqlite3.IntegrityError), store.connect() as conn:
        conn.execute("INSERT INTO rule_proposals (pattern, attack_type, status) "
                     "VALUES ('x', 'sqli', 'maybe')")


def test_reopening_an_existing_database_keeps_its_rows(store):
    with store.connect() as conn:
        conn.execute("INSERT INTO rule_proposals (pattern, attack_type) VALUES ('x', 'sqli')")
    again = LogStore(store.path)
    with again.connect() as conn:
        assert conn.execute("SELECT COUNT(*) FROM rule_proposals").fetchone()[0] == 1
