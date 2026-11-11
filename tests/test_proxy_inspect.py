import json
import logging

import httpx
import pytest

from ml import predict as predict_module
from proxy.decisions import Decision, ensure_visible, record
from tests.proxy_fakes import benign, malicious, proxy_client

pytestmark = pytest.mark.anyio


async def test_block_mode_refuses_malicious_requests_with_a_reason():
    decisions = []
    async with proxy_client("block", predictor=malicious, recorder=decisions.append) as c:
        r = await c.get("/search?q=x")
    assert r.status_code == 403
    assert r.headers["content-type"].startswith("text/plain")
    assert r.headers["x-content-type-options"] == "nosniff"
    assert "blocked because it looks like SQL injection" in r.text
    assert '"or 1=1"' in r.text
    assert decisions == [Decision(
        method="GET", path="/search", query="q=x", mode="block", action="blocked",
        label="malicious", score=0.97, reason=r.text,
    )]


async def test_blocked_requests_never_reach_the_upstream():
    seen = []

    def upstream(request):
        seen.append(request)
        raise AssertionError("should not be called")

    async with proxy_client("block", predictor=malicious,
                            transport=httpx.MockTransport(upstream)) as c:
        assert (await c.post("/login", content=b"x")).status_code == 403
    assert seen == []


@pytest.mark.parametrize("mode", ["block", "monitor"])
async def test_benign_requests_are_forwarded_and_recorded(mode):
    decisions = []
    async with proxy_client(mode, predictor=benign, recorder=decisions.append) as c:
        r = await c.get("/products?page=2")
    assert r.status_code == 200 and r.json()["raw_path"] == "/products"
    assert [d.action for d in decisions] == ["allowed"]
    assert decisions[0].label == "benign" and decisions[0].reason == ""


async def test_monitor_mode_forwards_malicious_requests_and_records_them():
    decisions = []
    async with proxy_client("monitor", predictor=malicious, recorder=decisions.append) as c:
        r = await c.post("/login?next=%2F", content=b"user=jo")
    assert r.status_code == 200
    assert r.json()["body"] == "user=jo"
    (d,) = decisions
    assert (d.action, d.mode, d.label, d.path, d.query) == (
        "flagged", "monitor", "malicious", "/login", "next=%2F")
    assert "SQL injection" in d.reason


async def test_classifier_sees_the_whole_request():
    calls = []

    def spy(request):
        calls.append(request)
        return benign(request)

    async with proxy_client(predictor=spy) as c:
        await c.put("/a%20b?q=%27x", content=b"body", headers={"user-agent": "ua"})
    (req,) = calls
    assert (req["method"], req["path"], req["query"], req["body"]) == ("PUT", "/a%20b", "q=%27x", "body")
    assert req["headers"]["user-agent"] == "ua"


def _broken(_request):
    raise RuntimeError("model file corrupt")


@pytest.mark.parametrize("mode, status", [("block", 503), ("monitor", 200)])
async def test_classifier_failure(mode, status):
    decisions = []
    async with proxy_client(mode, predictor=_broken, recorder=decisions.append) as c:
        r = await c.get("/")
    assert r.status_code == status
    assert [d.action for d in decisions] == ["error"]


def test_decisions_are_logged_as_json(caplog):
    caplog.set_level(logging.INFO, logger="chokidaar.decisions")
    record(Decision(method="GET", path="/", query="", mode="block", action="allowed",
                    label="benign", score=0.1))
    (entry,) = caplog.records
    assert json.loads(entry.getMessage())["action"] == "allowed"


def test_decisions_are_visible_when_logging_is_unconfigured(monkeypatch, capsys):
    # As under uvicorn: no root handlers, nothing set on the chokidaar loggers.
    base = logging.getLogger("chokidaar")
    monkeypatch.setattr(logging.getLogger(), "handlers", [])
    monkeypatch.setattr(base, "handlers", [])
    monkeypatch.setattr(base, "level", logging.NOTSET)
    ensure_visible()
    assert base.handlers  # stderr handler bound now, while capsys is active
    record(Decision(method="GET", path="/x", query="", mode="monitor", action="flagged"))
    assert '"action": "flagged"' in capsys.readouterr().err


@pytest.fixture
def fresh_model(tmp_path):
    predict_module.load(str(tmp_path / "missing.joblib"))


# No rule matches this, so the decision is the classifier's own.
MODEL_ONLY_ATTACK = {"name": "....//....//config.yml"}


async def test_real_classifier_blocks_an_attack(fresh_model):
    decisions = []
    async with proxy_client("block", predictor=None, recorder=decisions.append) as c:
        attack = await c.get("/files", params=MODEL_ONLY_ATTACK)
        normal = await c.get("/products", params={"page": "2", "sort": "price"})
    assert attack.status_code == 403
    assert "path traversal" in attack.text
    assert normal.status_code == 200
    assert [(d.action, d.rule) for d in decisions] == [("blocked", ""), ("allowed", "")]


async def test_real_classifier_in_monitor_mode_lets_attacks_through(fresh_model):
    decisions = []
    async with proxy_client("monitor", predictor=None, recorder=decisions.append) as c:
        r = await c.get("/files", params=MODEL_ONLY_ATTACK)
    assert r.status_code == 200
    assert (decisions[0].action, decisions[0].rule) == ("flagged", "")
