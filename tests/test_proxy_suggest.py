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
