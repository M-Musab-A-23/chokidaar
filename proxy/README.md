# proxy

Reverse proxy and rule engine. Every incoming request passes through here, is checked by the rules and the ML classifier, and is either forwarded to the protected app or blocked with an explanation.

## Running

```
UPSTREAM_URL=http://127.0.0.1:8000 MODE=block \
  uvicorn proxy.app:create_app --factory --port 8080 --no-server-header --no-date-header
```

| Variable | Meaning |
| --- | --- |
| `UPSTREAM_URL` | Required. The app to protect, e.g. `http://127.0.0.1:8000`. |
| `MODE` | `block` (default): malicious requests get `403` with a plain-language reason and never reach the app. `monitor`: everything is forwarded and the decision is only recorded. |
| `CHOKIDAAR_MODEL` | Optional model path (see `ml/README.md`). |

`--no-server-header --no-date-header` stop uvicorn adding its own `server` and `date` headers next to the ones from the app, so responses reach the client exactly as the app sent them.

## What happens to a request

1. The method, raw path, raw query, headers and the first 64 KiB of the body go to `ml.predict.predict()`.
2. The decision is recorded as one JSON line on the `chokidaar.decisions` logger (action `allowed`, `blocked`, `flagged` or `error`, with label, score and reason).
3. In block mode a malicious request is answered with `403`, `text/plain`. Otherwise the request is forwarded unchanged (apart from hop-by-hop headers and `Host`), and the app's status, headers and raw body are returned as they are. Redirects are not followed.

If the app cannot be reached the proxy answers `502` (`504` on timeout). If the classifier itself fails, monitor mode still forwards the request and block mode answers `503`.

Bodies are buffered in memory on the way in and out, so very large uploads and downloads use proportional memory. WebSockets are not proxied yet.
