"""The admin dashboard: a separate FastAPI app that reads the proxy's request
log (LOG_DB) and lets an admin review rule proposals.

Every /api route needs `Authorization: Bearer <ADMIN_TOKEN>`; the app refuses
to start without ADMIN_TOKEN. Values from the log are attacker-controlled, so
the API returns them as plain JSON data and the page only ever renders them as
text.
"""
import hmac
import os

from fastapi import Depends, FastAPI, Header, HTTPException

from proxy.logstore import LogStore


def token_from_env(environ=None) -> str:
    environ = os.environ if environ is None else environ
    token = environ.get("ADMIN_TOKEN", "").strip()
    if not token:
        raise RuntimeError("ADMIN_TOKEN is not set; the dashboard will not start without it")
    return token


def create_app(store: LogStore = None, token: str = None) -> FastAPI:
    """`store` defaults to a LogStore at LOG_DB and `token` to ADMIN_TOKEN."""
    token = token if token is not None else token_from_env()
    if not token.strip():
        raise RuntimeError("ADMIN_TOKEN is empty; the dashboard will not start without it")
    expected = token.encode()
    store = store or LogStore()

    def require_token(authorization: str = Header(default="")):
        scheme, _, given = authorization.partition(" ")
        if scheme.lower() != "bearer" or not hmac.compare_digest(given.strip().encode(), expected):
            raise HTTPException(401, "missing or wrong admin token",
                                headers={"WWW-Authenticate": "Bearer"})

    app = FastAPI(title="Chokidaar dashboard", docs_url=None, redoc_url=None, openapi_url=None)
    api = Depends(require_token)

    @app.middleware("http")
    async def security_headers(request, call_next):
        response = await call_next(request)
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self';"
            " connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'")
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.get("/api/summary", dependencies=[api])
    def summary():
        counts = store.counts()
        total = sum(counts.values())
        return {"counts": counts, "total": total,
                "blocked_share": counts["block"] / total if total else 0.0}

    return app
