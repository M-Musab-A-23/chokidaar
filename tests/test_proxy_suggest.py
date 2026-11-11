import json

import httpx
import pytest

from proxy.suggest import DEFAULT_MODEL, DEFAULT_URL, FakeClient, OllamaClient, SuggestError


def _ollama(handler, **kwargs):
    return OllamaClient(transport=httpx.MockTransport(handler), environ={}, **kwargs)


def test_ollama_settings_come_from_env_with_defaults():
    client = OllamaClient(environ={"SUGGEST_URL": "http://gpu-box:11434/", "SUGGEST_MODEL": "qwen"})
    assert (client.url, client.model) == ("http://gpu-box:11434", "qwen")
    client = OllamaClient(environ={"SUGGEST_URL": " ", "SUGGEST_MODEL": ""})
    assert (client.url, client.model) == (DEFAULT_URL, DEFAULT_MODEL)
    assert DEFAULT_URL == "http://localhost:11434"


def test_ollama_posts_the_prompt_and_returns_the_response():
    seen = []

    def handler(request):
        seen.append((request.method, str(request.url), json.loads(request.content)))
        return httpx.Response(200, json={"response": "[]", "done": True})

    assert _ollama(handler, model="m").complete("hello") == "[]"
    assert seen == [("POST", "http://localhost:11434/api/generate",
                     {"model": "m", "prompt": "hello", "stream": False})]


@pytest.mark.parametrize("response", [
    httpx.Response(500, text="model not found"),
    httpx.Response(200, text="not json"),
    httpx.Response(200, json={"error": "nope"}),
    httpx.Response(200, json={"response": 3}),
])
def test_ollama_failures_become_suggest_errors(response):
    with pytest.raises(SuggestError):
        _ollama(lambda request: response).complete("hello")


def test_ollama_unreachable_is_a_suggest_error():
    def handler(request):
        raise httpx.ConnectError("refused", request=request)

    with pytest.raises(SuggestError, match="localhost:11434"):
        _ollama(handler).complete("hello")


def test_fake_client_replays_answers_and_records_prompts():
    client = FakeClient("one", "two")
    assert [client.complete(p) for p in ("a", "b", "c")] == ["one", "two", "two"]
    assert client.prompts == ["a", "b", "c"]
    assert FakeClient().complete("x") == "[]"


from proxy.suggest import build_prompt, group_requests, parse_proposals  # noqa: E402


def _row(path="/item/1", query="", method="GET", rule_id=None, reason="r"):
    return {"method": method, "path": path, "query": query, "rule_id": rule_id, "reason": reason}


def test_requests_are_grouped_by_rule_method_and_path_shape():
    rows = [_row("/item/1", "id=1' or 1=1", rule_id="sqli-tautology"),
            _row("/item/22", "id=2' or 2=2", rule_id="sqli-tautology"),
            _row("/item/3", "q=<script>", rule_id=None),
            _row("/item/4", "id=1' or 1=1", method="POST", rule_id="sqli-tautology"),
            _row("/item/5", "id=5' or 5=5", rule_id="sqli-tautology")]
    groups = group_requests(rows)
    assert [(g.source, g.method, g.path, g.count) for g in groups] == [
        ("sqli-tautology", "GET", "/item/{n}", 3),
        ("ml", "GET", "/item/{n}", 1),
        ("sqli-tautology", "POST", "/item/{n}", 1),
    ]
    assert groups[0].examples == ["/item/1?id=1' or 1=1", "/item/22?id=2' or 2=2",
                                  "/item/5?id=5' or 5=5"]


def test_groups_keep_few_short_distinct_examples():
    rows = [_row(query="x=" + "a" * 500)] * 2 + [_row(query=f"x={i}") for i in range(10)]
    (group,) = group_requests(rows)
    assert group.count == 12
    assert len(group.examples) == 3
    assert group.examples[0].endswith("...") and len(group.examples[0]) == 203


def test_prompt_lists_groups_and_asks_for_json():
    prompt = build_prompt(group_requests([_row("/a", "q=<svg onload=x>", reason="xss reason")]))
    assert '"pattern"' in prompt and '"attack_type"' in prompt and '"rationale"' in prompt
    assert "sqli, xss, traversal, cmdi" in prompt
    assert "Group 1: 1 x GET /a, decided by the classifier" in prompt
    assert '"/a?q=<svg onload=x>"' in prompt
    assert "xss reason" in prompt


def test_prompt_is_capped_at_the_biggest_groups():
    rows = [_row(f"/p{chr(97 + i % 26)}{i // 26}") for i in range(30)]
    assert "Group 20:" in build_prompt(group_requests(rows))
    assert "Group 21:" not in build_prompt(group_requests(rows))


PROPOSAL = {"pattern": "abcd", "attack_type": "xss", "rationale": "r"}


@pytest.mark.parametrize("answer", [
    json.dumps([PROPOSAL]),
    "```json\n" + json.dumps([PROPOSAL]) + "\n```",
    "Here you go:\n" + json.dumps([PROPOSAL]) + "\nHope that helps.",
    json.dumps({"rules": [PROPOSAL]}),
])
def test_parse_proposals_accepts_common_answer_shapes(answer):
    assert parse_proposals(answer) == [PROPOSAL]


def test_parse_proposals_empty_list():
    assert parse_proposals("[]") == []


@pytest.mark.parametrize("answer", ["", "no idea", '{"a": 1}', "[1, 2", '"text"'])
def test_parse_proposals_rejects_anything_else(answer):
    with pytest.raises(SuggestError):
        parse_proposals(answer)


from proxy.suggest import ATTACK_TYPES, benign_payloads, validate  # noqa: E402

BENIGN = benign_payloads()


def _proposal(pattern=r"\bunion\s+all\s+select\b", attack_type="sqli", rationale="r"):
    return {"pattern": pattern, "attack_type": attack_type, "rationale": rationale}


def test_attack_types():
    assert ATTACK_TYPES == ("sqli", "xss", "traversal", "cmdi")


def test_benign_payloads_are_full_requests():
    assert len(BENIGN) > 10
    assert all(set(p) >= {"method", "path", "query", "headers", "body"} for p in BENIGN)
    assert {"query": "q=O'Reilly books"}.items() <= next(
        p for p in BENIGN if p["query"] == "q=O'Reilly books").items()


def test_missing_benign_file_is_an_error(tmp_path):
    with pytest.raises(SuggestError):
        benign_payloads(tmp_path / "nope.json")


@pytest.mark.parametrize("attack_type", ATTACK_TYPES)
def test_a_good_proposal_passes(attack_type):
    assert validate(_proposal(r"zz-attack-marker-\d+", attack_type), BENIGN) is None


@pytest.mark.parametrize("proposal, why", [
    ("not a dict", "not an object"),
    ({"attack_type": "sqli"}, "pattern is missing"),
    (_proposal(pattern=""), "pattern is missing"),
    (_proposal(pattern=42), "pattern is missing"),
    (_proposal(attack_type="sql_injection"), "attack_type must be one of"),
    (_proposal(attack_type=None), "attack_type must be one of"),
    (_proposal(rationale=["x"]), "rationale is not text"),
    (_proposal(pattern="a.b"), "shorter than 4"),
    (_proposal(pattern="(unclosed"), "does not compile"),
    (_proposal(pattern="(?:zzzz)?"), "matches the empty string"),
    (_proposal(pattern="x*y*z*"), "matches the empty string"),
    (_proposal(pattern=r"o'reilly"), "matches a benign payload"),
    (_proposal(pattern=r"\bselect\b"), "matches a benign payload"),
    (_proposal(pattern="^GET$"), "matches a benign payload"),
])
def test_bad_proposals_are_refused_with_a_reason(proposal, why):
    assert why in validate(proposal, BENIGN)


def test_benign_check_sees_url_decoded_text():
    benign = [{**BENIGN[0], "query": "q=hello%20world"}]
    assert "benign" in validate(_proposal(pattern="hello world", attack_type="xss"), benign)


from proxy.logstore import LogStore  # noqa: E402
from proxy.suggest import run  # noqa: E402

GOOD = {"pattern": r"zz-attack-marker-\d+", "attack_type": "sqli", "rationale": "marker"}


@pytest.fixture
def store(tmp_path):
    store = LogStore(str(tmp_path / "suggest.db"))
    store.add_request(method="GET", path="/item/1", query="id=1' or 1=1", body=b"",
                      decision="block", rule_id="sqli-tautology", reason="sql")
    store.add_request(method="GET", path="/ok", query="", body=b"", decision="allow")
    store.add_request(method="GET", path="/item/2", query="q=<x>", body=b"", decision="flagged")
    return store


def test_run_saves_valid_proposals_as_pending(store):
    bad = {"pattern": "a", "attack_type": "sqli", "rationale": ""}
    client = FakeClient(json.dumps([GOOD, bad, {**GOOD, "attack_type": "rce"}]))
    summary = run(store, client, benign=BENIGN)
    assert (summary.rows, summary.groups) == (2, 2)
    assert [p for _, p in summary.saved] == [GOOD]
    assert [why for _, why in summary.rejected] == [
        "pattern is shorter than 4 characters",
        "attack_type must be one of sqli, xss, traversal, cmdi, got 'rce'"]
    (saved,) = store.proposals()
    assert (saved["id"], saved["status"], saved["pattern"]) == (summary.saved[0][0], "pending",
                                                                GOOD["pattern"])


def test_run_prompt_contains_only_blocked_and_flagged_rows(store):
    client = FakeClient("[]")
    run(store, client, benign=BENIGN)
    (prompt,) = client.prompts
    assert "id=1' or 1=1" in prompt and "q=<x>" in prompt and "/ok" not in prompt


def test_run_respects_the_limit(store):
    client = FakeClient("[]")
    assert run(store, client, limit=1, benign=BENIGN).rows == 1
    assert "q=<x>" in client.prompts[0] and "or 1=1" not in client.prompts[0]


def test_run_skips_duplicates_already_stored_or_repeated(store):
    store.add_proposal(**GOOD)
    store.reject(store.proposals()[0]["id"])
    other = {**GOOD, "pattern": r"yy-attack-marker-\d+"}
    summary = run(store, FakeClient(json.dumps([GOOD, other, other])), benign=BENIGN)
    assert summary.duplicates == [GOOD, other]
    assert [p for _, p in summary.saved] == [other]
    assert len(store.proposals()) == 2


def test_dry_run_writes_nothing(store):
    summary = run(store, FakeClient(json.dumps([GOOD])), dry_run=True, benign=BENIGN)
    assert summary.saved == [(None, GOOD)]
    assert store.proposals() == []


def test_missing_rationale_is_stored_empty(store):
    run(store, FakeClient(json.dumps([{"pattern": GOOD["pattern"], "attack_type": "sqli"}])),
        benign=BENIGN)
    assert store.proposals()[0]["rationale"] == ""


def test_empty_log_does_not_ask_the_model(tmp_path):
    client = FakeClient()
    summary = run(LogStore(str(tmp_path / "empty.db")), client, benign=BENIGN)
    assert (summary.rows, summary.saved, client.prompts) == (0, [], [])


def test_unusable_answer_raises(store):
    with pytest.raises(SuggestError):
        run(store, FakeClient("sorry"), benign=BENIGN)


from proxy.suggest import build_parser, main  # noqa: E402


def test_cli_defaults_and_flags():
    args = build_parser().parse_args([])
    assert (args.limit, args.dry_run) == (200, False)
    args = build_parser().parse_args(["--limit", "5", "--dry-run"])
    assert (args.limit, args.dry_run) == (5, True)


@pytest.mark.parametrize("value", ["0", "-3", "many"])
def test_cli_refuses_a_bad_limit(value):
    with pytest.raises(SystemExit):
        build_parser().parse_args(["--limit", value])


def test_cli_saves_and_reports(store, capsys):
    bad = {"pattern": "(unclosed", "attack_type": "xss"}
    assert main([], client=FakeClient(json.dumps([GOOD, bad])), store=store) == 0
    out = capsys.readouterr().out
    assert "Read 2 blocked/flagged requests in 2 groups." in out
    assert "Saved 1 proposal(s):" in out and "#1 [sqli] zz-attack-marker" in out
    assert "Rejected 1 proposal(s):" in out and "does not compile" in out
    assert len(store.proposals()) == 1


def test_cli_dry_run_reports_without_saving(store, capsys):
    assert main(["--dry-run"], client=FakeClient(json.dumps([GOOD])), store=store) == 0
    assert "Would save 1 proposal(s):" in capsys.readouterr().out
    assert store.proposals() == []


def test_cli_reports_model_errors(store, capsys):
    assert main([], client=FakeClient("not json"), store=store) == 1
    assert capsys.readouterr().err.startswith("error: the model did not answer")
