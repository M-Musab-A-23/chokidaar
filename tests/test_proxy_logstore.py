import hashlib
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


def _rows(store):
    with store.connect() as conn:
        return [dict(r) for r in conn.execute("SELECT * FROM requests ORDER BY id")]


def test_add_request_stores_one_row(store):
    new_id = store.add_request(method="POST", path="/login", query="next=%2F",
                               body=b"user=' or 1=1 --", decision="block", ip="203.0.113.7",
                               rule_id="sqli-001", ml_score=0.97, reason="looks like SQL injection")
    (row,) = _rows(store)
    assert row["id"] == new_id
    assert {k: row[k] for k in ("ip", "method", "path", "query", "decision", "rule_id",
                                "ml_score", "reason")} == {
        "ip": "203.0.113.7", "method": "POST", "path": "/login", "query": "next=%2F",
        "decision": "block", "rule_id": "sqli-001", "ml_score": 0.97,
        "reason": "looks like SQL injection",
    }
    assert row["ts"].endswith("+00:00")


def test_body_is_stored_only_as_its_sha256(store):
    secret = b"password=hunter2"
    store.add_request(method="POST", path="/login", query="", body=secret, decision="allow")
    (row,) = _rows(store)
    assert row["body_hash"] == hashlib.sha256(secret).hexdigest()
    with open(store.path, "rb") as f:
        assert b"hunter2" not in f.read()


def test_optional_fields_may_be_empty(store):
    store.add_request(method="GET", path="/", query="", body=b"", decision="allow")
    (row,) = _rows(store)
    assert (row["ip"], row["rule_id"], row["ml_score"], row["reason"]) == (None, None, None, "")
    assert row["body_hash"] == hashlib.sha256(b"").hexdigest()


def test_unknown_decision_is_refused(store):
    with pytest.raises(ValueError):
        store.add_request(method="GET", path="/", query="", body=b"", decision="blocked")


def _add(store, decision="allow", ip="198.51.100.1", path="/"):
    return store.add_request(method="GET", path=path, query="", body=b"",
                             decision=decision, ip=ip)


def test_recent_returns_newest_first_up_to_the_limit(store):
    for i in range(5):
        _add(store, path=f"/{i}")
    assert [r["path"] for r in store.recent(3)] == ["/4", "/3", "/2"]
    assert len(store.recent()) == 5
    assert store.recent(0) == []


def test_recent_on_an_empty_log(store):
    assert store.recent(10) == []


def test_recent_filters_by_decision_and_ip(store):
    _add(store, "allow", "198.51.100.1", "/a")
    _add(store, "block", "198.51.100.1", "/b")
    _add(store, "block", "203.0.113.9", "/c")
    _add(store, "flagged", "203.0.113.9", "/d")
    assert [r["path"] for r in store.recent(decision="block")] == ["/c", "/b"]
    assert [r["path"] for r in store.recent(ip="203.0.113.9")] == ["/d", "/c"]
    assert [r["path"] for r in store.recent(decision="block", ip="198.51.100.1")] == ["/b"]
    assert [r["path"] for r in store.recent(1, decision="block")] == ["/c"]


def test_recent_refuses_an_unknown_decision(store):
    with pytest.raises(ValueError, match="decision must be one of"):
        store.recent(decision="blocked")


def test_counts_by_decision(store):
    assert store.counts() == {"allow": 0, "block": 0, "flagged": 0}
    for decision in ("allow", "allow", "block", "flagged", "allow"):
        _add(store, decision=decision)
    assert store.counts() == {"allow": 3, "block": 1, "flagged": 1}


def test_top_blocked_ips_counts_only_blocks(store):
    for ip, decision in [("10.0.0.1", "block"), ("10.0.0.1", "block"), ("10.0.0.1", "allow"),
                         ("10.0.0.2", "block"), ("10.0.0.2", "flagged"), ("10.0.0.2", "flagged"),
                         ("10.0.0.3", "block"), ("10.0.0.3", "block"), ("10.0.0.3", "block"),
                         ("10.0.0.4", "allow"), (None, "block")]:
        _add(store, decision=decision, ip=ip)
    assert store.top_blocked_ips() == [("10.0.0.3", 3), ("10.0.0.1", 2), ("10.0.0.2", 1)]
    assert store.top_blocked_ips(limit=2) == [("10.0.0.3", 3), ("10.0.0.1", 2)]


def test_top_blocked_ips_breaks_ties_by_ip(store):
    for ip in ("10.0.0.9", "10.0.0.5"):
        _add(store, decision="block", ip=ip)
    assert store.top_blocked_ips() == [("10.0.0.5", 1), ("10.0.0.9", 1)]


def test_blocked_and_flagged_skips_allowed_and_is_newest_first(store):
    for i, decision in enumerate(["block", "allow", "flagged", "block", "allow"]):
        _add(store, decision=decision, path=f"/{i}")
    assert [r["path"] for r in store.blocked_and_flagged()] == ["/3", "/2", "/0"]
    assert [r["path"] for r in store.blocked_and_flagged(limit=2)] == ["/3", "/2"]
    assert store.blocked_and_flagged(limit=0) == []


def test_add_proposal_stores_a_pending_row(store):
    new_id = store.add_proposal(pattern=r"\bsleep\s*\(", attack_type="sqli", rationale="timing")
    assert store.proposals() == [{"id": new_id, "pattern": r"\bsleep\s*\(",
                                  "attack_type": "sqli", "rationale": "timing",
                                  "status": "pending"}]


def test_add_proposal_skips_duplicates(store):
    assert store.add_proposal(pattern="abcd", attack_type="xss") is not None
    assert store.add_proposal(pattern="abcd", attack_type="xss", rationale="again") is None
    assert store.add_proposal(pattern="abcd", attack_type="cmdi") is not None
    assert len(store.proposals()) == 2


def test_proposals_filters_by_status(store):
    store.add_proposal(pattern="abcd", attack_type="xss")
    assert len(store.proposals("pending")) == 1
    assert store.proposals("approved") == []
    with pytest.raises(ValueError):
        store.proposals("maybe")


def test_approve_and_reject_change_the_status(store):
    first = store.add_proposal(pattern="abcd", attack_type="xss")
    second = store.add_proposal(pattern="efgh", attack_type="xss")
    store.approve(first)
    store.reject(second)
    assert [p["id"] for p in store.proposals("approved")] == [first]
    assert [p["id"] for p in store.proposals("rejected")] == [second]
    store.approve(second)
    assert store.proposals("rejected") == []


def test_approve_or_reject_an_unknown_id_raises(store):
    with pytest.raises(KeyError):
        store.approve(42)
    with pytest.raises(KeyError):
        store.reject(42)
