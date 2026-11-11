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

1. The method, raw path, raw query, headers and the first 64 KiB of the body are checked against the signature rules in `proxy/rules.py` (SQL injection, XSS, path traversal, command injection). Each part is checked as sent, after each of up to three rounds of URL decoding, and with HTML entities decoded. On a hit the rule decides (label `malicious`, score `1.0`) and the classifier is not called.
2. Otherwise the same parts go to `ml.predict.predict()`.
3. The decision is recorded as one JSON line on the `chokidaar.decisions` logger (action `allowed`, `blocked`, `flagged` or `error`, with label, score, reason and the id of the rule that matched, if any).
4. In block mode a malicious request is answered with `403`, `text/plain`. Otherwise the request is forwarded unchanged (apart from hop-by-hop headers and `Host`), and the app's status, headers and raw body are returned as they are. Redirects are not followed.

If the app cannot be reached the proxy answers `502` (`504` on timeout). If the classifier itself fails, monitor mode still forwards the request and block mode answers `503`.

Bodies are buffered in memory on the way in and out, so very large uploads and downloads use proportional memory. WebSockets are not proxied yet.

## Rules

Each rule in `proxy.rules.RULES` has an `id`, an `attack_type`, a case-insensitive `regex` and a `description` used in the block reason, which names the attack, the part of the request it was found in and the matching text. `proxy.rules.scan(request)` returns every matching rule; the proxy uses the first. `tests/attacks/payloads.json` holds malicious and benign payloads for each attack type; every malicious one must hit a rule of its type and no benign one may hit any rule.
