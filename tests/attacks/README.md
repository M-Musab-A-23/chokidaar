# attack tests

One test file per attack class (SQL injection, XSS, path traversal, command injection, ...). Each test sends a malicious payload that must be blocked and a normal request that must pass.

Payloads here are sent only to the local test apps started by Docker Compose, never to any external site.
