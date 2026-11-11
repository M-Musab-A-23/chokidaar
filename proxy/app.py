"""The reverse proxy: every request is checked by the signature rules and, if no
rule matches, by the classifier, then either refused with a plain-language reason (MODE=block) or forwarded to UPSTREAM_URL,
whose response is passed back unchanged. MODE=monitor forwards everything and
only records what it would have done.

Run with: uvicorn proxy.app:create_app --factory
"""
import logging
from contextlib import asynccontextmanager

import httpx
from fastapi import FastAPI, Request, Response
from fastapi.responses import PlainTextResponse
from starlette.concurrency import run_in_threadpool
from starlette.routing import request_response

from ml import predict as ml_predict
from proxy.config import Settings, from_env
from proxy.decisions import Decision, ensure_visible, record
from proxy.extract import to_ml_request
from proxy.logstore import LogStore
from proxy.reason import explain
from proxy.rules import first_match

logger = logging.getLogger("chokidaar.proxy")

# Headers that describe one connection, not the message; they are never forwarded
# (RFC 9110, section 7.6.1). Host is rewritten by the client for the upstream.
HOP_BY_HOP = {
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "proxy-connection", "te", "trailer", "transfer-encoding", "upgrade",
}
UPSTREAM_TIMEOUT = httpx.Timeout(30.0, connect=5.0)
WARM_UP_REQUEST = {"method": "GET", "path": "/", "query": "", "headers": {}, "body": ""}
CLASSIFIER_FAILED = "The classifier failed, so the request could not be checked."
# Decision.action -> requests.decision in the log store. "error" is stored as
# what actually happened to the request: refused (block) or forwarded (allow).
STORED_DECISION = {"allowed": "allow", "blocked": "block", "flagged": "flagged"}


def _hop_by_hop(headers: list) -> set:
    names = set(HOP_BY_HOP)
    for name, value in headers:
        if name.lower() == b"connection":
            names.update(v.strip().lower() for v in value.decode("latin-1").split(","))
    return names


def _without(headers: list, drop: set) -> list:
    return [(k, v) for k, v in headers if k.decode("latin-1").lower() not in drop]


def _raw_path(request: Request) -> bytes:
    raw = request.scope.get("raw_path") or request.url.path.encode()
    return raw.split(b"?", 1)[0]


async def _forward(client: httpx.AsyncClient, upstream: str, request: Request,
                   body: bytes) -> Response:
    url = upstream + _raw_path(request).decode("latin-1")
    query = request.scope.get("query_string", b"")
    if query:
        url += "?" + query.decode("latin-1")
    headers = _without(request.headers.raw, _hop_by_hop(request.headers.raw) | {"host", "content-length"})
    upstream_request = client.build_request(request.method, url, headers=headers, content=body)
    try:
        upstream_response = await client.send(upstream_request, stream=True)
    except httpx.TimeoutException:
        return PlainTextResponse("The protected site took too long to respond.", status_code=504)
    except httpx.TransportError:
        return PlainTextResponse("The protected site could not be reached.", status_code=502)
    try:
        # Raw bytes, so compressed bodies stay compressed and match their headers.
        content = b"".join([chunk async for chunk in upstream_response.aiter_raw()])
    finally:
        await upstream_response.aclose()
    return _pass_through(upstream_response, content, request.method)


def _pass_through(upstream_response: httpx.Response, content: bytes, method: str) -> Response:
    raw = upstream_response.headers.raw
    headers = _without(raw, _hop_by_hop(raw))
    status = upstream_response.status_code
    has_length = any(k.lower() == b"content-length" for k, _ in headers)
    if not has_length and method != "HEAD" and status >= 200 and status not in (204, 304):
        # The body arrived chunked and is now buffered, so its length is known.
        headers.append((b"content-length", str(len(content)).encode()))
    response = Response(content=content, status_code=status)
    response.raw_headers = headers
    return response


def _blocked(reason: str) -> Response:
    # text/plain plus nosniff: the reason quotes parts of the request and must
    # never be rendered as HTML.
    return PlainTextResponse(
        reason, status_code=403, headers={"x-content-type-options": "nosniff"}
    )


def _check(predictor, settings: Settings, ml_request: dict):
    """Returns (decision, response to send instead of forwarding, or None)."""
    base = dict(method=ml_request["method"], path=ml_request["path"],
                query=ml_request["query"], mode=settings.mode)
    hit = first_match(ml_request)
    if hit is not None:
        # A known attack signature: decided here, the classifier is not asked.
        fields = dict(base, label="malicious", score=1.0, reason=hit.reason, rule=hit.rule_id)
        if settings.mode == "block":
            return Decision(**fields, action="blocked"), _blocked(hit.reason)
        return Decision(**fields, action="flagged"), None
    try:
        result = predictor(ml_request)
    except Exception:
        logger.exception("classifier failed on %s %s", base["method"], base["path"])
        decision = Decision(**base, action="error", reason=CLASSIFIER_FAILED)
        if settings.mode == "block":
            return decision, PlainTextResponse(
                "This request could not be checked, so it was not let through. "
                "Please try again later.", status_code=503,
            )
        return decision, None
    label, score = result["label"], float(result["score"])
    if label != "malicious":
        return Decision(**base, action="allowed", label=label, score=score), None
    top_features = result.get("top_features") or []
    if settings.mode == "block":
        reason = explain(top_features)
        return Decision(**base, action="blocked", label=label, score=score, reason=reason), \
            _blocked(reason)
    reason = explain(top_features, flagged=True)
    return Decision(**base, action="flagged", label=label, score=score, reason=reason), None


async def _store(store: LogStore, decision: Decision, request: Request, body: bytes,
                 refused: bool) -> None:
    """Write the request to the log store. Never raises: a broken log must not
    turn into a broken request."""
    if decision.action == "error":
        stored = "block" if refused else "allow"
    else:
        stored = STORED_DECISION[decision.action]
    try:
        await run_in_threadpool(
            store.add_request, method=decision.method, path=decision.path,
            query=decision.query, body=body, decision=stored,
            ip=request.client.host if request.client else None,
            rule_id=decision.rule or None,
            ml_score=None if decision.action == "error" else decision.score,
            reason=decision.reason,
        )
    except Exception:
        logger.exception("could not write %s %s to the request log",
                         decision.method, decision.path)


def create_app(settings: Settings = None, transport: httpx.AsyncBaseTransport = None,
               predictor=None, recorder=None, store: LogStore = None) -> FastAPI:
    """`predictor` defaults to ml.predict.predict, `recorder` to
    proxy.decisions.record and `store` to a LogStore at LOG_DB; all can be
    swapped out in tests."""
    settings = settings or from_env()
    store = store or LogStore()
    if recorder is None:
        recorder = record
        ensure_visible()
    client = httpx.AsyncClient(
        transport=transport, timeout=UPSTREAM_TIMEOUT, follow_redirects=False
    )

    @asynccontextmanager
    async def lifespan(_app):
        if predictor is None:
            # Load (or train) the model before the first request, not during it.
            # predict() loads it only if it is not loaded already.
            await run_in_threadpool(ml_predict.predict, WARM_UP_REQUEST)
        yield
        await client.aclose()

    # No docs or schema routes: every path belongs to the protected app.
    app = FastAPI(lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)
    app.state.settings = settings

    async def proxy(request: Request) -> Response:
        body = await request.body()
        ml_request = to_ml_request(request.method, _raw_path(request),
                                   request.scope.get("query_string", b""),
                                   request.headers.raw, body)
        # Rules and classifier are CPU-bound and synchronous; keep them off the event loop.
        decision, refusal = await run_in_threadpool(
            _check, predictor or ml_predict.predict, settings, ml_request
        )
        recorder(decision)
        await _store(store, decision, request, body, refused=refusal is not None)
        if refusal is not None:
            return refusal
        return await _forward(client, settings.upstream_url, request, body)

    # Mounted as a plain ASGI app so it receives every path and every HTTP method
    # (a normal route would answer 405 to methods it does not list, e.g. PROPFIND).
    app.mount("", request_response(proxy))
    return app
