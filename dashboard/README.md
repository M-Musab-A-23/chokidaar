# dashboard

Admin UI: live request and block logs, risk score per IP and endpoint, attack timeline, and approval of suggested rules.

## Running

```
ADMIN_TOKEN=change-me LOG_DB=logs/chokidaar.db python -m dashboard
```

Then open http://127.0.0.1:8081 and enter the token once. It is kept in `sessionStorage`, so it is forgotten when the tab closes; **Sign out** forgets it straight away.

| Variable / option | Meaning |
| --- | --- |
| `ADMIN_TOKEN` | Required. The dashboard refuses to start without it. Use a long random value, e.g. `python -c "import secrets; print(secrets.token_urlsafe(32))"`. |
| `LOG_DB` | The proxy's SQLite request log, default `logs/chokidaar.db`. Point both at the same file. |
| `DASHBOARD_PORT`, `--port` | Port to listen on, default `8081`. `--port` wins. |
| `--host` | Address to listen on, default `127.0.0.1`. |

It can also be started with `uvicorn dashboard.app:create_app --factory --port 8081`.

With Docker, `ADMIN_TOKEN=... docker compose up` also starts the `dashboard` service on the same log volume as the proxy, published on `127.0.0.1:8081` only. The dashboard serves plain HTTP, so put it behind TLS before exposing it beyond the host.

## What it shows

The page refreshes every 5 seconds:

- **Summary cards**: total requests, allowed, blocked, flagged and the share blocked.
- **Attack timeline**: requests and blocked requests per hour for the last 24 hours (UTC hours, labelled in local time).
- **Top blocked IPs**: select one to filter the request table to it.
- **Recent requests**: the newest 100, filtered by decision and/or IP.
- **Rule suggestions**: proposals from `python -m proxy.suggest` with **Approve** and **Reject**. Approved rules take effect when the proxy restarts.

## API

Every `/api` route needs `Authorization: Bearer <ADMIN_TOKEN>` and answers `401` without it. `/` and `/static/` need no token; they hold no data.

| Route | Returns |
| --- | --- |
| `GET /api/summary` | `{counts: {allow, block, flagged}, total, blocked_share}` |
| `GET /api/requests?limit=50&decision=&ip=` | Newest rows of the request log. `limit` is 1-500; `decision` is `allow`, `block` or `flagged`. |
| `GET /api/top-ips?limit=10` | `[{ip, blocks}]`, most blocks first. |
| `GET /api/timeline` | 24 entries `{hour, requests, blocks}`, oldest first; `hour` is the start of a UTC hour. |
| `GET /api/suggestions?status=` | Rule proposals, optionally only `pending`, `approved` or `rejected`. |
| `POST /api/suggestions/{id}/approve`, `/reject` | The updated proposal, or `404` for an unknown id. |

## Security

Paths, queries, IPs, reasons and rule patterns in the log come from whoever sent the request. The API returns them as JSON data, and the page only ever puts them on screen as text (`textContent`), never as HTML. Every response carries a strict `Content-Security-Policy` (scripts and styles from the dashboard itself only, no framing), `X-Content-Type-Options: nosniff` and `Cache-Control: no-store`. The page loads nothing from other sites.
