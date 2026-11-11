"""A fake upstream app and a client for the proxy tests."""
import gzip
from contextlib import asynccontextmanager

import httpx
from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse
from starlette.routing import request_response

from proxy.app import create_app
from proxy.config import Settings

UPSTREAM = "http://upstream.test"
GZIPPED = gzip.compress(b"compressed hello")


def fake_upstream() -> FastAPI:
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

    @app.get("/cookies")
    def cookies():
        r = Response(content=b"made", status_code=201, media_type="text/plain")
        r.headers.append("set-cookie", "a=1; Path=/")
        r.headers.append("set-cookie", "b=2; Path=/")
        r.headers["x-upstream"] = "yes"
        return r

    @app.get("/gzip")
    def gzipped():
        return Response(content=GZIPPED, headers={"content-encoding": "gzip"},
                        media_type="text/plain")

    @app.get("/redirect")
    def redirect():
        return Response(status_code=302, headers={"location": "/elsewhere"})

    @app.get("/broken")
    def broken():
        return Response(content=b"upstream failed", status_code=500)

    async def echo(request: Request):
        return JSONResponse({
            "method": request.method,
            "raw_path": request.scope["raw_path"].decode(),
            "query": request.scope["query_string"].decode(),
            "headers": dict(request.headers.items()),
            "body": (await request.body()).decode(),
        })

    app.mount("", request_response(echo))
    return app


def benign(_request: dict) -> dict:
    return {"score": 0.01, "label": "benign", "top_features": []}


def malicious(_request: dict) -> dict:
    return {"score": 0.97, "label": "malicious",
            "top_features": ["sql keyword pattern", 'fragment "or 1=1"']}


@asynccontextmanager
async def proxy_client(mode: str = "block", transport: httpx.AsyncBaseTransport = None,
                       predictor=benign, **kwargs):
    """An httpx client talking to the proxy, which talks to the fake upstream.
    Pass predictor=None to use the real classifier."""
    kwargs["predictor"] = predictor
    transport = transport or httpx.ASGITransport(app=fake_upstream())
    app = create_app(Settings(upstream_url=UPSTREAM, mode=mode), transport=transport, **kwargs)
    async with app.router.lifespan_context(app):
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app),
                                     base_url="http://proxy.test") as client:
            yield client
