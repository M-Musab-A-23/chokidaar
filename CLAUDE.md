# Chokidaar: guide for Claude Code

## What this project is
Chokidaar is an AI-powered Web Application Firewall (WAF) built for CS-484 Information Security at NUST SEECS.
It runs as a reverse proxy in front of a web app, blocks malicious HTTP requests using a rule engine plus an ML classifier,
explains why each request was blocked, and shows attacks on an admin dashboard.

## Team and workflow
- Two members. Never push to main; work on a feature branch (feat/..., fix/...) and open a pull request.
- The other member reviews and approves every PR. Squash-merge only.
- Reference the issue in the PR description (Closes #N).

## Planned stack (update as decisions are made)
- Python 3.12, FastAPI for the proxy and dashboard API
- scikit-learn for the ML classifier
- SQLite for request and block logs
- pytest for tests
- Docker Compose to run Chokidaar in front of OWASP Juice Shop or DVWA

## Folder layout
- proxy/: reverse proxy and rule engine
- ml/: feature extraction, training scripts, model loading
- dashboard/: admin UI (logs, risk scores, rule approvals)
- tests/: unit tests; tests/attacks/ holds attack payload tests
- docs/: threat model, report drafts, diagrams

## Rules
- Never commit secrets, API keys, datasets or trained model files. Use .env (gitignored).
- Every detection rule or model change needs a test: one malicious payload that must be blocked and one normal request that must pass.
- Only send attack payloads to the local test apps started by Docker Compose. Never to any external site.
- Mock all LLM calls in tests; CI has no API keys.
- Keep functions small and commented so both members can explain any part in the viva.
- Run pytest -q before opening a PR.
