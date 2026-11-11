from datetime import datetime, timezone

import httpx
import pytest

from dashboard.app import create_app, token_from_env
from proxy.logstore import LogStore

pytestmark = pytest.mark.anyio

TOKEN = "test-admin-token"
AUTH = {"Authorization": f"Bearer {TOKEN}"}


@pytest.fixture
def store(tmp_path):
    return LogStore(str(tmp_path / "dashboard.db"))


@pytest.fixture
async def client(store):
    app = create_app(store=store, token=TOKEN)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),
                                 base_url="http://dashboard") as c:
        yield c


def log(store, decision="allow", ip="198.51.100.1", path="/", **kw):
    return store.add_request(method="GET", path=path, query="", body=b"",
                             decision=decision, ip=ip, **kw)


# --- startup and auth ---

def test_refuses_to_start_without_admin_token(monkeypatch):
    monkeypatch.delenv("ADMIN_TOKEN", raising=False)
    with pytest.raises(RuntimeError, match="ADMIN_TOKEN is not set"):
        create_app()
    monkeypatch.setenv("ADMIN_TOKEN", "   ")
    with pytest.raises(RuntimeError, match="ADMIN_TOKEN is not set"):
        create_app()


def test_token_comes_from_admin_token():
    assert token_from_env({"ADMIN_TOKEN": " s3cret "}) == "s3cret"


def test_an_empty_token_argument_is_refused(store):
    with pytest.raises(RuntimeError, match="ADMIN_TOKEN is empty"):
        create_app(store=store, token="")


@pytest.mark.parametrize("headers", [
    {},
    {"Authorization": "Bearer wrong"},
    {"Authorization": TOKEN},
    {"Authorization": f"Basic {TOKEN}"},
    {"Authorization": "Bearer "},
])
async def test_api_needs_the_bearer_token(client, headers):
    r = await client.get("/api/summary", headers=headers)
    assert r.status_code == 401
    assert r.headers["WWW-Authenticate"] == "Bearer"


async def test_responses_carry_security_headers(client):
    r = await client.get("/api/summary", headers=AUTH)
    assert "default-src 'self'" in r.headers["Content-Security-Policy"]
    assert r.headers["X-Content-Type-Options"] == "nosniff"
    assert r.headers["X-Frame-Options"] == "DENY"
    assert r.headers["Cache-Control"] == "no-store"


# --- summary ---

async def test_summary_counts_each_decision(client, store):
    for decision in ("allow", "allow", "block", "flagged"):
        log(store, decision)
    r = await client.get("/api/summary", headers=AUTH)
    assert r.status_code == 200
    assert r.json() == {"counts": {"allow": 2, "block": 1, "flagged": 1},
                        "total": 4, "blocked_share": 0.25}


async def test_summary_on_an_empty_log(client):
    r = await client.get("/api/summary", headers=AUTH)
    assert r.json() == {"counts": {"allow": 0, "block": 0, "flagged": 0},
                        "total": 0, "blocked_share": 0.0}


# --- requests ---

async def test_requests_are_newest_first_with_a_limit(client, store):
    for i in range(5):
        log(store, path=f"/{i}")
    r = await client.get("/api/requests", params={"limit": 3}, headers=AUTH)
    assert r.status_code == 200
    assert [row["path"] for row in r.json()] == ["/4", "/3", "/2"]
    assert set(r.json()[0]) >= {"id", "ts", "ip", "method", "path", "query",
                                "decision", "rule_id", "ml_score", "reason"}


async def test_requests_filter_by_decision_and_ip(client, store):
    log(store, "allow", "198.51.100.1", "/a")
    log(store, "block", "198.51.100.1", "/b")
    log(store, "block", "203.0.113.9", "/c")
    r = await client.get("/api/requests", params={"decision": "block"}, headers=AUTH)
    assert [row["path"] for row in r.json()] == ["/c", "/b"]
    r = await client.get("/api/requests", params={"ip": "198.51.100.1"}, headers=AUTH)
    assert [row["path"] for row in r.json()] == ["/b", "/a"]
    r = await client.get("/api/requests", params={"decision": "block", "ip": "198.51.100.1"},
                         headers=AUTH)
    assert [row["path"] for row in r.json()] == ["/b"]


@pytest.mark.parametrize("params", [{"decision": "blocked"}, {"limit": 0}, {"limit": 501}])
async def test_requests_refuse_bad_parameters(client, params):
    r = await client.get("/api/requests", params=params, headers=AUTH)
    assert r.status_code == 422


# --- top IPs ---

async def test_top_ips_count_blocks_most_first(client, store):
    for ip in ("203.0.113.9", "203.0.113.9", "198.51.100.1"):
        log(store, "block", ip)
    log(store, "allow", "192.0.2.5")
    r = await client.get("/api/top-ips", headers=AUTH)
    assert r.json() == [{"ip": "203.0.113.9", "blocks": 2}, {"ip": "198.51.100.1", "blocks": 1}]
    r = await client.get("/api/top-ips", params={"limit": 1}, headers=AUTH)
    assert r.json() == [{"ip": "203.0.113.9", "blocks": 2}]


# --- timeline ---

async def test_timeline_has_24_hours_ending_with_the_current_one(store):
    now = datetime(2026, 11, 11, 10, 42, tzinfo=timezone.utc)
    log(store, "block", ts="2026-11-10T10:59:00.000+00:00")   # 24h ago: outside
    log(store, "allow", ts="2026-11-10T11:00:00.000+00:00")
    log(store, "block", ts="2026-11-10T11:20:00.000+00:00")
    log(store, "block", ts="2026-11-11T10:41:00.000+00:00")
    log(store, "flagged", ts="2026-11-11T10:41:30.000+00:00")
    app = create_app(store=store, token=TOKEN, clock=lambda: now)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),
                                 base_url="http://dashboard") as c:
        r = await c.get("/api/timeline", headers=AUTH)
    hours = r.json()
    assert len(hours) == 24
    assert hours[0] == {"hour": "2026-11-10T11:00:00Z", "requests": 2, "blocks": 1}
    assert hours[-1] == {"hour": "2026-11-11T10:00:00Z", "requests": 2, "blocks": 1}
    assert all(h == {"hour": h["hour"], "requests": 0, "blocks": 0} for h in hours[1:-1])
