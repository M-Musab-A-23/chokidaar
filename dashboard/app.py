"""The admin dashboard: a separate FastAPI app that reads the proxy's request
log (LOG_DB) and lets an admin review rule proposals.

Every /api route needs `Authorization: Bearer <ADMIN_TOKEN>`; the app refuses
to start without ADMIN_TOKEN. Values from the log are attacker-controlled, so
the API returns them as plain JSON data and the page only ever renders them as
text.
"""
import hmac
import os
from datetime import datetime, timedelta, timezone
from typing import Literal, Optional

from fastapi import Depends, FastAPI, Header, HTTPException, Query

from proxy.logstore import LogStore


def token_from_env(environ=None) -> str:
    environ = os.environ if environ is None else environ
    token = environ.get("ADMIN_TOKEN", "").strip()
    if not token:
        raise RuntimeError("ADMIN_TOKEN is not set; the dashboard will not start without it")
    return token


TIMELINE_HOURS = 24


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def create_app(store: LogStore = None, token: str = None, clock=_utcnow) -> FastAPI:
    """`store` defaults to a LogStore at LOG_DB and `token` to ADMIN_TOKEN;
    `clock` (returning an aware datetime) can be swapped out in tests."""
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

    @app.get("/api/requests", dependencies=[api])
    def requests(limit: int = Query(50, ge=1, le=500),
                 decision: Optional[Literal["allow", "block", "flagged"]] = None,
                 ip: Optional[str] = Query(None, max_length=64)):
        return store.recent(limit, decision=decision, ip=ip or None)

    @app.get("/api/top-ips", dependencies=[api])
    def top_ips(limit: int = Query(10, ge=1, le=100)):
        return [{"ip": ip, "blocks": blocks} for ip, blocks in store.top_blocked_ips(limit)]

    @app.get("/api/timeline", dependencies=[api])
    def timeline():
        """Requests and blocks per UTC hour for the last 24 hours, the current
        hour last; hours without requests are included at 0."""
        current = clock().astimezone(timezone.utc).replace(minute=0, second=0, microsecond=0)
        start = current - timedelta(hours=TIMELINE_HOURS - 1)
        counts = store.hourly(start)
        hours = []
        for i in range(TIMELINE_HOURS):
            hour = start + timedelta(hours=i)
            requests_, blocks = counts.get(hour.strftime("%Y-%m-%dT%H"), (0, 0))
            hours.append({"hour": hour.strftime("%Y-%m-%dT%H:00:00Z"),
                          "requests": requests_, "blocks": blocks})
        return hours

    @app.get("/api/suggestions", dependencies=[api])
    def suggestions(status: Optional[Literal["pending", "approved", "rejected"]] = None):
        return store.proposals(status)

    def set_status(proposal_id: int, change) -> dict:
        try:
            change(proposal_id)
        except KeyError:
            raise HTTPException(404, f"no rule proposal with id {proposal_id}")
        (row,) = [p for p in store.proposals() if p["id"] == proposal_id]
        return row

    @app.post("/api/suggestions/{proposal_id}/approve", dependencies=[api])
    def approve(proposal_id: int):
        """The proxy loads approved rules on its next start."""
        return set_status(proposal_id, store.approve)

    @app.post("/api/suggestions/{proposal_id}/reject", dependencies=[api])
    def reject(proposal_id: int):
        return set_status(proposal_id, store.reject)

    return app
