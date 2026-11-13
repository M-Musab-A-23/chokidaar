# Integration guide

This guide is the starting point for anyone building on Chokidaar. It describes what exists today, how the parts connect, the interfaces that must not break, and the work that is still open on the web side. Read it before changing code.

## 1. The project in one paragraph

Chokidaar is a reverse-proxy web application firewall. It sits in front of one web application, inspects every inbound HTTP request (method, path, query, headers, first 64 KiB of the body), and either forwards it or refuses it with `403` and a plain-language reason. Detection is two layers: 21 signature rules first, then a machine-learning classifier. Every decision is written to a SQLite log, which an admin dashboard reads. A background job turns blocked traffic into suggested new rules that an admin approves. It ships as `docker compose up` (with OWASP Juice Shop as the protected app) or as a single `chokidaar.exe`.

Stack: Python 3.12, FastAPI, httpx, uvicorn, SQLite, scikit-learn, pytest, GitHub Actions, Docker, PyInstaller.

## 2. Ownership

The project has two tracks.

| Track | Owns | Folders |
| --- | --- | --- |
| Detection and ML | The classifier, its features, training data and evaluation, the threshold, and the `predict()` contract | `ml/`, `docs/evaluation.md` |
| Web | The proxy, rules, request log, rule suggestions, dashboard, packaging and the end-to-end attack tests | `proxy/`, `dashboard/`, `tests/attacks/`, `Dockerfile`, `docker-compose.yml`, `scripts/` |

The detection track is finished. To get the system working end to end, a first version of every web-track part was also built and merged. Treat that code as the base for the web track: own it, extend it, and refactor it where it helps, as long as the interfaces in section 4 stay intact. Section 6 lists what is still open.

## 3. What exists today

### Detection and ML (`ml/`)

| File | What it does |
| --- | --- |
| `ml/text.py` | Joins method, path, query, five headers (`user-agent`, `referer`, `cookie`, `content-type`, `x-forwarded-for`) and body into one string, URL-decodes up to twice and lower-cases it. |
| `ml/features.py` | Hand-made features: length, special characters, percent-encoding ratio, digit ratio, and pattern hits for SQL, script, traversal and shell attacks. |
| `ml/model.py` | `Classifier`: character 2-4-gram TF-IDF plus the hand-made features into a logistic regression. `explain()` names the features behind a malicious call. |
| `ml/data.py` | A seeded generator of normal and malicious requests, and `load_csic()` for the CSIC 2010 dataset. |
| `ml/csic.py` | Loads the three CSIC 2010 files and splits the attacks in half with a fixed seed (train / test). |
| `ml/train.py` | `python -m ml.train [--csic]` trains and saves `models/model.joblib`. `--csic` adds the CSIC training split. |
| `ml/predict.py` | `predict(request)`, the only function the proxy calls. Loads the model once. |
| `ml/evaluate.py`, `ml/evaluate_csic.py` | Precision, recall, F1, false alarm rate, threshold trade-off and time per request. |

Results on CSIC 2010 (full details in `docs/evaluation.md`): rules plus the classifier trained on generated data and the CSIC split reach F1 0.954 with a 2.5% false alarm rate at threshold 0.5, and about 1.2 ms per request. At threshold 0.8 the false alarm rate drops to 0.3% with 88% recall. A model trained only on generated data catches about 20% of CSIC attacks, so the model must be trained on traffic that looks like the protected application.

### Web side (`proxy/`, `dashboard/`, packaging)

| File | What it does |
| --- | --- |
| `proxy/app.py` | The FastAPI reverse proxy (`create_app` factory). Rules, then classifier, then block or forward. Passes upstream responses through unchanged. `502` if the app is down, `504` on timeout, `503` in block mode if the classifier fails. |
| `proxy/extract.py` | Turns an ASGI request into the dict `predict()` and the rules expect. |
| `proxy/rules.py` | The 21 signature rules, `scan()`, `first_match()`, and `custom_rules(store)` for approved proposals. |
| `proxy/reason.py` | Turns the classifier's `top_features` into the sentence shown to the visitor. |
| `proxy/decisions.py` | The `Decision` record, logged as one JSON line on the `chokidaar.decisions` logger. |
| `proxy/logstore.py` | `LogStore`: the SQLite request log and rule proposals, with read helpers for the dashboard. |
| `proxy/suggest.py` | `python -m proxy.suggest [--limit N] [--dry-run]`: asks a local model (Ollama) for new rules, validates them, saves them as pending. |
| `proxy/config.py`, `proxy/cli.py` | Settings from the environment; the `chokidaar.exe` command line. |
| `dashboard/app.py`, `dashboard/static/` | Token-protected admin dashboard (FastAPI + one static page, no build step). |
| `Dockerfile`, `docker-compose.yml` | Juice Shop, the proxy on 8080 and the dashboard on 127.0.0.1:8081, sharing one log volume. |
| `scripts/build_exe.ps1` | Trains the model and builds `dist\chokidaar.exe`. |

Tests: 358, all in `tests/`, run by CI on every push and pull request.

## 4. Interfaces that must not break

These are the seams between the two tracks. Change them only together, in one pull request, with tests on both sides.

### 4.1 `ml.predict.predict(request) -> dict`

Input, built by `proxy/extract.py`:

```python
{
    "method": "POST",                 # upper case
    "path": "/rest/user/login",       # raw, still URL-encoded
    "query": "next=%2F",              # raw, still URL-encoded, no leading "?"
    "headers": {"user-agent": "..."}, # lower-case names, repeated names joined with ", "
    "body": "email=a%40b.c&pw=x",     # first 64 KiB, decoded as UTF-8 with replacement
}
```

Output:

```python
{
    "score": 0.97,          # float between 0 and 1
    "label": "malicious",   # "malicious" if score >= threshold, else "benign"
    "top_features": ["sql keyword pattern", 'fragment "or 1=1"'],  # empty for benign
}
```

- The classifier decodes the path, query and body itself; pass them raw.
- `top_features` entries are either `"<kind> pattern"` (kinds: `sql keyword`, `script tag or handler`, `path traversal`, `shell command`) or `fragment "<text>"`. `proxy/reason.py` depends on these two shapes.
- The model loads once per process. The proxy calls `predict()` once at startup to warm it up.
- `predict()` is synchronous and CPU-bound; the proxy runs it in a thread pool. Keep it that way.

### 4.2 Classifier settings

| Variable | Default | Meaning |
| --- | --- | --- |
| `CHOKIDAAR_MODEL` | `models/model.joblib` | Trained model file. If it is missing, a model is trained on generated data at startup (slow, and weaker on real traffic). |
| `CHOKIDAAR_THRESHOLD` | `0.5` | Score at or above which a request is malicious. Must be above 0 and at most 1. |

### 4.3 Signature rules

`proxy/rules.py`: each `Rule` has `id`, `attack_type` (`sql_injection`, `xss`, `path_traversal`, `command_injection`), a case-insensitive `regex` and a `description`. `first_match(request)` returns a `Match` with `rule_id` and `reason`, or `None`. A rule hit is final: label `malicious`, score `1.0`, the classifier is not called. Rule ids appear in the log and on the dashboard, so do not rename existing ones.

### 4.4 Request log schema (SQLite, `LOG_DB`, default `logs/chokidaar.db`)

```sql
CREATE TABLE requests (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    ts        TEXT NOT NULL,          -- UTC, ISO 8601
    ip        TEXT,                   -- connection address; X-Forwarded-For is not trusted
    method    TEXT NOT NULL,
    path      TEXT NOT NULL,          -- raw, URL-encoded
    query     TEXT NOT NULL DEFAULT '',
    body_hash TEXT NOT NULL,          -- SHA-256 of the full body; the body is never stored
    decision  TEXT NOT NULL CHECK (decision IN ('allow', 'block', 'flagged')),
    rule_id   TEXT,                   -- rule that decided; NULL when the classifier decided
    ml_score  REAL,                   -- 1.0 for rule hits; NULL if the classifier failed
    reason    TEXT NOT NULL DEFAULT ''
);

CREATE TABLE rule_proposals (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    pattern     TEXT NOT NULL,
    attack_type TEXT NOT NULL,        -- sqli, xss, traversal, cmdi
    rationale   TEXT NOT NULL DEFAULT '',
    status      TEXT NOT NULL DEFAULT 'pending'
                CHECK (status IN ('pending', 'approved', 'rejected'))
);
```

All access goes through `LogStore` (`add_request`, `recent`, `counts`, `top_blocked_ips`, `hourly`, `blocked_and_flagged`, `add_proposal`, `proposals`, `approve`, `reject`). Add new queries there, not in the dashboard. Writes from the proxy never raise: a broken log must not break a request.

### 4.5 Dashboard API (`dashboard/app.py`, port 8081)

Every `/api` route needs `Authorization: Bearer <ADMIN_TOKEN>`. The app refuses to start without `ADMIN_TOKEN`.

| Route | Returns |
| --- | --- |
| `GET /api/summary` | `{counts: {allow, block, flagged}, total, blocked_share}` |
| `GET /api/requests?limit=&decision=&ip=` | Newest requests first (rows of the `requests` table); `limit` 1-500, default 50 |
| `GET /api/top-ips?limit=` | `[{ip, blocks}]` |
| `GET /api/timeline` | 24 entries `{hour, requests, blocks}`, UTC, oldest first |
| `GET /api/suggestions?status=` | Rows of `rule_proposals` |
| `POST /api/suggestions/{id}/approve` and `/reject` | The updated proposal; `404` for an unknown id |

Approved rules are loaded by the proxy at startup, with ids `custom-<id>`.

### 4.6 Decision log line

Each request also produces one JSON line on the `chokidaar.decisions` logger:

```json
{"method": "GET", "path": "/", "query": "id=1%27%20OR%201=1--", "mode": "block",
 "action": "blocked", "label": "malicious", "score": 1.0,
 "reason": "This request was blocked because ...", "rule": "sqli-tautology"}
```

`action` is `allowed`, `blocked`, `flagged` or `error`.

### 4.7 Configuration and ports

| Variable | Used by | Default |
| --- | --- | --- |
| `UPSTREAM_URL` | proxy | required |
| `MODE` | proxy | `block` (or `monitor`) |
| `LOG_DB` | proxy, dashboard, suggestions | `logs/chokidaar.db` |
| `ADMIN_TOKEN` | dashboard | required |
| `DASHBOARD_PORT` | dashboard | `8081` |
| `SUGGEST_URL`, `SUGGEST_MODEL` | suggestions | `http://localhost:11434`, `llama3.1` |

Proxy: port 8080. Dashboard: 8081, bound to `127.0.0.1` in Compose.
