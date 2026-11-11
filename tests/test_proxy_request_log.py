import hashlib

import pytest

from proxy.logstore import LogStore
from tests.proxy_fakes import benign, malicious, proxy_client

pytestmark = pytest.mark.anyio


@pytest.fixture
def store(tmp_path):
    return LogStore(str(tmp_path / "requests.db"))


# No signature rule matches this, so the decision comes from the classifier.
MODEL_ONLY_PATH = "/files/....//....//config.yml"


async def test_blocked_request_is_logged_with_its_reason(store):
    asked = []

    def spy(request):
        asked.append(request)
        return malicious(request)

    async with proxy_client("block", predictor=spy, store=store) as c:
        r = await c.post(MODEL_ONLY_PATH + "?next=%2F", content=b"user=jo")
    assert len(asked) == 1, "the classifier should decide, not a rule"
    assert r.status_code == 403
    (row,) = store.recent()
    assert (row["method"], row["path"], row["query"], row["decision"]) == (
        "POST", MODEL_ONLY_PATH, "next=%2F", "block")
    assert row["ip"] == "127.0.0.1"
    assert row["ml_score"] == 0.97
    assert row["reason"] == r.text
    assert row["rule_id"] is None
    assert row["body_hash"] == hashlib.sha256(b"user=jo").hexdigest()


async def test_rule_hit_is_logged_with_its_rule_id(store):
    def must_not_be_asked(_request):
        raise AssertionError("a rule hit should not reach the classifier")

    async with proxy_client("block", predictor=must_not_be_asked, store=store) as c:
        r = await c.post("/login?next=%2F", content=b"user=' or 1=1 --")
    assert r.status_code == 403
    (row,) = store.recent()
    assert (row["decision"], row["rule_id"]) == ("block", "sqli-tautology")
    assert (row["method"], row["path"], row["query"]) == ("POST", "/login", "next=%2F")
    assert row["reason"] == r.text


async def test_flagged_request_is_logged_as_flagged(store):
    async with proxy_client("monitor", predictor=malicious, store=store) as c:
        assert (await c.get("/search?q=x")).status_code == 200
    (row,) = store.recent()
    assert row["decision"] == "flagged"
    assert row["reason"].startswith("This request was flagged because")
    assert "blocked" not in row["reason"]


@pytest.mark.parametrize("mode", ["block", "monitor"])
async def test_allowed_request_is_logged(store, mode):
    async with proxy_client(mode, predictor=benign, store=store) as c:
        await c.get("/products?page=2")
    (row,) = store.recent()
    assert (row["decision"], row["path"], row["query"], row["reason"]) == (
        "allow", "/products", "page=2", "")
    assert row["ml_score"] == 0.01


def _broken(_request):
    raise RuntimeError("model file corrupt")


@pytest.mark.parametrize("mode, stored", [("block", "block"), ("monitor", "allow")])
async def test_classifier_failure_is_logged_as_what_happened(store, mode, stored):
    async with proxy_client(mode, predictor=_broken, store=store) as c:
        await c.get("/")
    (row,) = store.recent()
    assert row["decision"] == stored
    assert row["ml_score"] is None
    assert "could not be checked" in row["reason"]


async def test_one_row_per_request(store):
    async with proxy_client("block", predictor=benign, store=store) as c:
        for i in range(3):
            await c.get(f"/page/{i}")
    assert [r["path"] for r in store.recent()] == ["/page/2", "/page/1", "/page/0"]
    assert store.counts()["allow"] == 3


class BrokenStore:
    def add_request(self, **_row):
        raise OSError("disk full")


@pytest.mark.parametrize("mode, predictor, status", [
    ("block", benign, 200), ("block", malicious, 403), ("monitor", malicious, 200)])
async def test_a_failing_log_never_breaks_the_request(mode, predictor, status, caplog):
    async with proxy_client(mode, predictor=predictor, store=BrokenStore()) as c:
        r = await c.get("/products")
    assert r.status_code == status
    assert "could not write GET /products to the request log" in caplog.text


async def test_an_unusable_log_path_does_not_stop_the_proxy(tmp_path):
    # The log path is a directory, so SQLite cannot open it as a database.
    async with proxy_client("block", predictor=benign, store=LogStore(str(tmp_path))) as c:
        assert (await c.get("/")).status_code == 200


async def test_default_store_is_at_log_db(temporary_log_db):
    async with proxy_client("block", predictor=malicious) as c:
        await c.get("/")
    assert LogStore(str(temporary_log_db)).counts()["block"] == 1
