# Threat model

## What is protected

One web application placed behind Chokidaar. The goal is to stop malicious inbound HTTP requests from reaching it, and to give the operator a record of what was tried.

## Attacker

Anyone who can send HTTP requests to the proxy: an anonymous visitor, an automated scanner, or a user with a valid account. The attacker can choose the method, path, query, headers, cookies and body, and can encode them in several ways.

## In scope

| Attack | Example | How it is caught |
| --- | --- | --- |
| SQL injection | `id=1' OR 1=1 --`, `UNION SELECT`, `SLEEP(5)`, `HAVING 1=1` | Rules `sqli-*`, then the classifier |
| Cross-site scripting | `<script>`, `onerror=`, `javascript:` | Rules `xss-*`, then the classifier |
| Path traversal | `../../etc/passwd`, `..%2f`, overlong UTF-8 | Rules `traversal-*`, then the classifier |
| Command injection | `; cat /etc/passwd`, `$(whoami)`, shellshock | Rules `cmdi-*`, then the classifier |
| Encoded variants | Double URL encoding, mixed case, comment padding | Repeated decoding before both rules and classifier |

## Out of scope

- Responses from the application are not inspected.
- HTTPS is not terminated here. Put a TLS terminator in front, or use plain HTTP on a trusted network.
- WebSockets are not proxied.
- Only the first 64 KiB of a request body is inspected; the full body is still forwarded.
- Logic flaws, broken access control, stolen credentials and denial of service by volume.
- Attacks that need no malicious-looking request, such as abusing a legitimate but weak feature.

## Risk matrix

| Risk | Likelihood | Impact | Mitigation | Residual risk |
| --- | --- | --- | --- | --- |
| Attack payload that no rule and not the classifier recognises (false negative) | Medium | High | Rules plus classifier, regular retraining, suggested rules from the block log | Some novel payloads will get through |
| Legitimate request blocked (false positive) | Medium | Medium | Benign near-miss tests, `monitor` mode for a trial period, plain-language reason with contact advice | Unusual content such as code in a Markdown body can be blocked |
| Attack hidden beyond the first 64 KiB of a body | Low | High | Limit is documented; size can be raised | Open |
| Encoding tricks the decoder does not cover | Medium | High | Up to three rounds of URL decoding and HTML entity decoding | Other encodings, such as base64 inside a field, are not decoded |
| Block reason used to attack the client (reflected content) | Low | Medium | Refusals are `text/plain` with `nosniff` | Low |
| Log injection or stored XSS through the dashboard | Medium | High | Log values are always inserted as text; strict Content-Security-Policy; no inline script | Low |
| Admin dashboard exposed or guessed | Medium | High | Required `ADMIN_TOKEN`, no start without it, bound to localhost in Compose | Plain HTTP; use TLS before exposing it |
| Poisoned rule suggestion (a model proposes a harmful rule) | Low | Medium | Every proposal is validated (compiles, known type, never matches the benign samples) and needs human approval | Admin error |
| Classifier or proxy failure | Low | High | Block mode fails closed with `503`; monitor mode fails open | Choice of fail closed or open is per mode |
| Proxy bypassed by reaching the application directly | Medium | High | In Compose the application is not published to the host; only the proxy is | Depends on the operator's network setup |
| Spoofed client IP in the log | Medium | Low | The connection address is logged and `X-Forwarded-For` is not trusted | Behind another proxy all requests show that proxy's IP |

## Assumptions

- The application is reachable only through Chokidaar.
- The operator reviews the dashboard and keeps the model and rules up to date.
- The log database is stored on a disk only the operator can read.
