"""Turn an incoming request into the dict the classifier expects."""

# Only the first part of a large body is inspected, so one huge upload cannot
# stall the classifier. The full body is still forwarded.
MAX_INSPECTED_BODY = 64 * 1024


def _text(raw: bytes) -> str:
    return raw.decode("utf-8", errors="replace")


def to_ml_request(method: str, raw_path: bytes, query: bytes, headers, body: bytes) -> dict:
    """Path and query stay URL-encoded: the classifier does its own decoding.

    `headers` is a list of (name, value) byte pairs as ASGI gives them; repeated
    names are joined with ", ".
    """
    joined = {}
    for name, value in headers:
        key, val = _text(name).lower(), _text(value)
        joined[key] = f"{joined[key]}, {val}" if key in joined else val
    return {
        "method": method.upper(),
        "path": _text(raw_path),
        "query": _text(query),
        "headers": joined,
        "body": _text(body[:MAX_INSPECTED_BODY]),
    }
