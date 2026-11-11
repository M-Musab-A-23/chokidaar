"""Rule suggestions: read recent blocked and flagged requests from the request
log, group similar ones, ask a language model for regex rules that would catch
them, check every proposal and save the good ones as pending rule proposals
for an admin to approve or reject.

The model is reached through a small client interface (`complete(prompt) ->
str`). The default client talks to a local Ollama server; tests use FakeClient.

Run with: python -m proxy.suggest [--limit N] [--dry-run]
"""
import os
from typing import Protocol

import httpx

DEFAULT_URL = "http://localhost:11434"
DEFAULT_MODEL = "llama3.1"
MODEL_TIMEOUT = httpx.Timeout(120.0, connect=5.0)


class SuggestError(Exception):
    """The model could not be reached or gave an answer that cannot be used."""


class ModelClient(Protocol):
    def complete(self, prompt: str) -> str:
        """The model's text answer to `prompt`."""


class OllamaClient:
    """Asks a local Ollama server, using SUGGEST_URL and SUGGEST_MODEL."""

    def __init__(self, url: str = None, model: str = None,
                 transport: httpx.BaseTransport = None, environ=None):
        environ = os.environ if environ is None else environ
        self.url = (url or environ.get("SUGGEST_URL", "").strip() or DEFAULT_URL).rstrip("/")
        self.model = model or environ.get("SUGGEST_MODEL", "").strip() or DEFAULT_MODEL
        self._transport = transport

    def complete(self, prompt: str) -> str:
        payload = {"model": self.model, "prompt": prompt, "stream": False}
        try:
            with httpx.Client(transport=self._transport, timeout=MODEL_TIMEOUT) as client:
                response = client.post(f"{self.url}/api/generate", json=payload)
                response.raise_for_status()
                answer = response.json()["response"]
        except httpx.HTTPError as exc:
            raise SuggestError(f"could not get an answer from {self.url} "
                               f"(model {self.model}): {exc}") from exc
        except (ValueError, KeyError, TypeError) as exc:
            raise SuggestError(f"unexpected answer from {self.url}: {exc}") from exc
        if not isinstance(answer, str):
            raise SuggestError(f"unexpected answer from {self.url}: response is not text")
        return answer


class FakeClient:
    """Returns canned answers in order (the last one repeats) and keeps every
    prompt it was given. For tests: it never touches the network."""

    def __init__(self, *answers: str):
        self.answers = list(answers) or ["[]"]
        self.prompts = []

    def complete(self, prompt: str) -> str:
        self.prompts.append(prompt)
        index = min(len(self.prompts), len(self.answers)) - 1
        return self.answers[index]
