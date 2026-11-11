"""Turn a request dict into one normalised string for the classifier."""
from urllib.parse import unquote_plus

KEPT_HEADERS = ("user-agent", "referer", "cookie", "content-type", "x-forwarded-for")


def decode(value: str, rounds: int = 2) -> str:
    """URL-decode repeatedly so double-encoded payloads are exposed."""
    for _ in range(rounds):
        decoded = unquote_plus(value)
        if decoded == value:
            break
        value = decoded
    return value


def request_to_text(request: dict) -> str:
    """Join the parts of a request that can carry an attack, decoded and lower-cased."""
    headers = request.get("headers") or {}
    header_text = " ".join(
        str(v) for k, v in headers.items() if str(k).lower() in KEPT_HEADERS
    )
    parts = [
        str(request.get("method") or ""),
        str(request.get("path") or ""),
        str(request.get("query") or ""),
        header_text,
        str(request.get("body") or ""),
    ]
    return decode(" ".join(parts)).lower()
