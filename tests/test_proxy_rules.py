import httpx
import pytest

from tests.proxy_fakes import benign, proxy_client

pytestmark = pytest.mark.anyio

SQLI = {"id": "1' OR 1=1--"}


def _must_not_run(_request):
    raise AssertionError("the classifier should not be called after a rule hit")


async def test_rule_hit_blocks_before_the_classifier_and_the_upstream():
    decisions = []

    def upstream(_request):
        raise AssertionError("should not be called")

    async with proxy_client("block", predictor=_must_not_run, recorder=decisions.append,
                            transport=httpx.MockTransport(upstream)) as c:
        r = await c.get("/item", params=SQLI)
    assert r.status_code == 403
    assert r.headers["x-content-type-options"] == "nosniff"
    assert "SQL injection" in r.text and "query string" in r.text
    (d,) = decisions
    assert (d.action, d.rule, d.label, d.score) == ("blocked", "sqli-tautology", "malicious", 1.0)
    assert d.reason == r.text


async def test_rules_see_headers_and_body():
    decisions = []
    async with proxy_client("block", predictor=_must_not_run, recorder=decisions.append) as c:
        header = await c.get("/", headers={"user-agent": "() { :; }; /bin/bash -c id"})
        body = await c.post("/comment", content=b"text=%3Cscript%3Ealert(1)%3C%2Fscript%3E")
    assert header.status_code == body.status_code == 403
    assert "user-agent header" in header.text
    assert [d.rule.split("-")[0] for d in decisions] == ["cmdi", "xss"]


async def test_monitor_mode_forwards_a_rule_hit_and_flags_it():
    decisions = []
    async with proxy_client("monitor", predictor=_must_not_run, recorder=decisions.append) as c:
        r = await c.get("/item", params=SQLI)
    assert r.status_code == 200
    assert r.json()["query"] == "id=1%27+OR+1%3D1--"
    (d,) = decisions
    assert (d.action, d.rule) == ("flagged", "sqli-tautology")


async def test_requests_without_a_rule_hit_go_to_the_classifier():
    calls = []

    def spy(request):
        calls.append(request)
        return benign(request)

    decisions = []
    async with proxy_client("block", predictor=spy, recorder=decisions.append) as c:
        r = await c.get("/search", params={"q": "O'Reilly books"})
    assert r.status_code == 200
    assert len(calls) == 1
    assert (decisions[0].action, decisions[0].rule) == ("allowed", "")
