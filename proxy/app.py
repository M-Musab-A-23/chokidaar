"""The reverse proxy: every request is forwarded to UPSTREAM_URL and the
upstream response is passed back unchanged.

Run with: uvicorn proxy.app:create_app --factory
"""
from contextlib import asynccontextmanager

import httpx
from fastapi import FastAPI, Request, Response
from fastapi.responses import PlainTextResponse
from starlette.routing import request_response

from proxy.config import Settings, from_env

# Headers that describe one connection, not the message; they are never forwarded
# (RFC 9110, section 7.6.1). Host is rewritten by the client for the upstream.
HOP_BY_HOP = {
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "proxy-connection", "te", "trailer", "transfer-encoding", "upgrade",
}
UPSTREAM_TIMEOUT = httpx.Timeout(30.0, connect=5.0)


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


def create_app(settings: Settings = None, transport: httpx.AsyncBaseTransport = None) -> FastAPI:
    settings = settings or from_env()
    client = httpx.AsyncClient(
        transport=transport, timeout=UPSTREAM_TIMEOUT, follow_redirects=False
    )

    @asynccontextmanager
    async def lifespan(_app):
        yield
        await client.aclose()

    # No docs or schema routes: every path belongs to the protected app.
    app = FastAPI(lifespan=lifespan, docs_url=None, redoc_url=None, openapi_url=None)
    app.state.settings = settings

    async def proxy(request: Request) -> Response:
        body = await request.body()
        return await _forward(client, settings.upstream_url, request, body)

    # Mounted as a plain ASGI app so it receives every path and every HTTP method
    # (a normal route would answer 405 to methods it does not list, e.g. PROPFIND).
    app.mount("", request_response(proxy))
    return app
