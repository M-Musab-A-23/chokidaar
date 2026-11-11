# attack tests

`payloads.json` lists malicious and benign payloads per attack type, each written as the request parts it is sent in. `test_rule_payloads.py` checks the signature rules against all of them: a malicious payload must hit a rule of its attack type, a benign one must hit none. Add a payload there whenever a rule misses an attack or blocks a normal request.

One test file per attack class (SQL injection, XSS, path traversal, command injection, ...). Each test sends a malicious payload that must be blocked and a normal request that must pass.

Payloads here are sent only to the local test apps started by Docker Compose, never to any external site.
