"""Explain a block in words a site visitor or admin can understand."""

ATTACK_NAMES = {
    "sql keyword pattern": "SQL injection (an attempt to run database commands)",
    "script tag or handler pattern": "cross-site scripting (an attempt to run scripts in the browser)",
    "path traversal pattern": "path traversal (an attempt to read files outside the website)",
    "shell command pattern": "command injection (an attempt to run commands on the server)",
}
FRAGMENT_PREFIX = "fragment "
# The model's fragments are character n-grams; short ones like "scr" or "/s"
# mean nothing to a reader, so only longer ones are quoted back.
MIN_FRAGMENT_LENGTH = 4


def _fragments(top_features: list) -> list:
    quoted = [f[len(FRAGMENT_PREFIX):] for f in top_features if f.startswith(FRAGMENT_PREFIX)]
    return [q for q in quoted if len(q.strip('"').strip()) >= MIN_FRAGMENT_LENGTH]


def explain(top_features: list, flagged: bool = False) -> str:
    """The reason for a block, shown to the visitor. With flagged=True (monitor
    mode, the request was let through) it says "flagged" and is meant only for
    the admin, so it has no "contact the administrator" line."""
    kinds = [ATTACK_NAMES[f] for f in top_features if f in ATTACK_NAMES]
    fragments = _fragments(top_features)
    verb = "flagged" if flagged else "blocked"
    what = _join(kinds) if kinds else "an attack on this website"
    text = f"This request was {verb} because it looks like {what}."
    if fragments:
        text += " Suspicious parts: " + ", ".join(fragments) + "."
    if flagged:
        return text
    return text + " If you think this is a mistake, contact the site administrator."


def _join(items: list) -> str:
    return items[0] if len(items) == 1 else ", ".join(items[:-1]) + " and " + items[-1]
