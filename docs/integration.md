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
