"""Hand-made numeric features that sit next to the character n-grams."""
import re

import numpy as np

from ml.text import request_to_text

KEYWORDS = {
    "sql keyword": [
        r"union\s+(all\s+)?select", r"select\s.+\sfrom", r"\bor\s+\d+\s*=\s*\d+",
        r"\band\s+\d+\s*=\s*\d+", r"'\s*or\s*'", r"drop\s+table", r"insert\s+into",
        r"sleep\s*\(", r"benchmark\s*\(", r"information_schema", r"--\s", r"/\*.*\*/",
    ],
    "script tag or handler": [
        r"<\s*script", r"javascript:", r"\bon\w+\s*=", r"<\s*img[^>]+src", r"<\s*iframe",
        r"<\s*svg", r"document\.cookie", r"alert\s*\(",
    ],
    "path traversal": [r"\.\./", r"\.\.\\", r"/etc/passwd", r"boot\.ini", r"win\.ini", r"\.\.%2f"],
    "shell command": [
        r"[;|&`]\s*(cat|ls|id|whoami|wget|curl|nc|bash|sh|rm|ping)\b", r"\$\(.+\)",
        r"/bin/(ba)?sh", r"\bcmd(\.exe)?\b",
    ],
}
_COMPILED = {name: [re.compile(p) for p in pats] for name, pats in KEYWORDS.items()}
SPECIAL = set("'\"<>;()|&`$\\{}[]%=")
GROUPS = list(KEYWORDS)
FEATURE_NAMES = (
    ["length", "special_chars", "special_ratio", "encoded_ratio", "digit_ratio"]
    + [f"hits: {g}" for g in GROUPS]
)


def hand_features(request: dict) -> list:
    raw = " ".join(str(request.get(k) or "") for k in ("path", "query", "body"))
    text = request_to_text(request)
    n = max(len(text), 1)
    special = sum(1 for ch in text if ch in SPECIAL)
    encoded = len(re.findall(r"%[0-9a-fA-F]{2}", raw))
    digits = sum(ch.isdigit() for ch in text)
    hits = [sum(1 for rx in _COMPILED[g] if rx.search(text)) for g in GROUPS]
    return [
        float(np.log1p(len(text))), float(np.log1p(special)), special / n,
        encoded / max(len(raw), 1), digits / n, *map(float, hits),
    ]
