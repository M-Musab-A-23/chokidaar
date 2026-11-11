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
