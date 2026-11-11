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
