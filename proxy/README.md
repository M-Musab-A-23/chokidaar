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
| `LOG_DB` | SQLite request log, default `logs/chokidaar.db`. The directory is created if needed. |

`--no-server-header --no-date-header` stop uvicorn adding its own `server` and `date` headers next to the ones from the app, so responses reach the client exactly as the app sent them.

## What happens to a request

1. The method, raw path, raw query, headers and the first 64 KiB of the body are checked against the signature rules in `proxy/rules.py` (SQL injection, XSS, path traversal, command injection). Each part is checked as sent, after each of up to three rounds of URL decoding, and with HTML entities decoded. On a hit the rule decides (label `malicious`, score `1.0`) and the classifier is not called.
2. Otherwise the same parts go to `ml.predict.predict()`.
3. The decision is recorded as one JSON line on the `chokidaar.decisions` logger (action `allowed`, `blocked`, `flagged` or `error`, with label, score, reason and the id of the rule that matched, if any), and as one row in the request log (see below).
4. In block mode a malicious request is answered with `403`, `text/plain`. Otherwise the request is forwarded unchanged (apart from hop-by-hop headers and `Host`), and the app's status, headers and raw body are returned as they are. Redirects are not followed.

If the app cannot be reached the proxy answers `502` (`504` on timeout). If the classifier itself fails, monitor mode still forwards the request and block mode answers `503`.

Bodies are buffered in memory on the way in and out, so very large uploads and downloads use proportional memory. WebSockets are not proxied yet.

## Rules

Each rule in `proxy.rules.RULES` has an `id`, an `attack_type`, a case-insensitive `regex` and a `description` used in the block reason, which names the attack, the part of the request it was found in and the matching text. `proxy.rules.scan(request)` returns every matching rule; the proxy uses the first. `tests/attacks/payloads.json` holds malicious and benign payloads for each attack type; every malicious one must hit a rule of its type and no benign one may hit any rule.

## Request log

`proxy/logstore.py` keeps one row per request in the `requests` table of the `LOG_DB` database:

| Column | Meaning |
| --- | --- |
| `id`, `ts` | Row id and UTC time (ISO 8601). |
| `ip` | The client address of the connection. `X-Forwarded-For` is not trusted. |
| `method`, `path`, `query` | As received; path and query stay URL-encoded. |
| `body_hash` | SHA-256 of the full body. The body itself is never stored. |
| `decision` | `allow`, `block` or `flagged` (malicious but let through in monitor mode). A request the classifier could not check is stored as what happened to it: `block` in block mode, `allow` in monitor mode, with no `ml_score`. |
| `rule_id` | The rule that matched; empty when the classifier decided. |
| `ml_score`, `reason` | Classifier score and the plain-language reason. |

The same database holds `rule_proposals` (`pattern`, `attack_type`, `rationale`, `status` = `pending`, `approved` or `rejected`) for the admin to review.

The row is written after the decision and before the request is forwarded. If writing fails (disk full, bad path, locked database) the error is logged on `chokidaar.proxy` and the request carries on as if nothing happened.

`LogStore` also has read helpers for the dashboard: `recent(limit)`, `counts()` (requests per decision) and `top_blocked_ips(limit)`.

`LogStore` also has `blocked_and_flagged(limit)`, `add_proposal(...)`, `proposals(status)`, `approve(id)` and `reject(id)` for rule suggestions (below).

## Rule suggestions

`proxy/suggest.py` asks a language model to propose new signature rules based on what the proxy has recently blocked or flagged. Nothing it proposes is used until an admin approves it.

```
python -m proxy.suggest [--limit N] [--dry-run]
```

1. The newest `N` (default 200) blocked and flagged rows are read from the request log.
2. Similar rows are grouped: same deciding rule (or the classifier), same method and the same path once numbers are ignored. The 20 largest groups go into the prompt, each with its count, reason and up to three example paths with query strings. Request bodies are never in the log, so the model never sees them. The examples are marked as untrusted data in the prompt.
3. The model is asked for a JSON list of `{"pattern", "attack_type", "rationale"}`. A code fence or text around the list is tolerated; any other answer is an error and nothing is saved.
4. Every proposal is checked. It is rejected, with the reason printed, if the regex does not compile, `attack_type` is not one of `sqli`, `xss`, `traversal` or `cmdi`, the pattern is shorter than 4 characters, it matches the empty string, or it matches any benign payload in `tests/attacks/payloads.json` (checked exactly as the proxy would check it, after URL and HTML entity decoding).
5. Valid proposals are saved in `rule_proposals` with status `pending`. A pattern already proposed for the same attack type, whatever its status, is skipped, so a rejected rule is not proposed again. `--dry-run` prints what would be saved and writes nothing.

| Variable | Meaning |
| --- | --- |
| `SUGGEST_URL` | Ollama server, default `http://localhost:11434`. |
| `SUGGEST_MODEL` | Model name, default `llama3.1`. |
| `LOG_DB` | The request log to read and write, as for the proxy. |

The model client is pluggable: anything with a `complete(prompt) -> str` method can be passed to `proxy.suggest.run(store, client, ...)`. `OllamaClient` is the default and `FakeClient` returns canned answers for tests, which never use the network.

To review proposals:

```
python -c "from proxy.logstore import LogStore; print(*LogStore().proposals('pending'), sep='
')"
python -c "from proxy.logstore import LogStore; LogStore().approve(3)"
python -c "from proxy.logstore import LogStore; LogStore().reject(4)"
```

When the proxy starts, it loads every approved proposal as a rule with id `custom-<id>`. Built-in rules are checked first. A block by a custom rule tells the visitor the request contains "a pattern the site administrator added as an attack signature"; the model's rationale is never shown to visitors. Approving or rejecting takes effect the next time the proxy starts. An approved proposal that no longer compiles is skipped with a warning on `chokidaar.proxy`, and if the log cannot be read the proxy starts with the built-in rules only.
