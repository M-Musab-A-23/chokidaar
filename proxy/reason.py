"""Explain a block in words a site visitor or admin can understand."""

ATTACK_NAMES = {
    "sql keyword pattern": "SQL injection (an attempt to run database commands)",
    "script tag or handler pattern": "cross-site scripting (an attempt to run scripts in the browser)",
    "path traversal pattern": "path traversal (an attempt to read files outside the website)",
    "shell command pattern": "command injection (an attempt to run commands on the server)",
}
FRAGMENT_PREFIX = "fragment "


def explain(top_features: list) -> str:
    kinds = [ATTACK_NAMES[f] for f in top_features if f in ATTACK_NAMES]
    fragments = [f[len(FRAGMENT_PREFIX):] for f in top_features if f.startswith(FRAGMENT_PREFIX)]
    if kinds:
        text = "This request was blocked because it looks like " + _join(kinds) + "."
    else:
        text = "This request was blocked because it looks like an attack on this website."
    if fragments:
        text += " Suspicious parts: " + ", ".join(fragments) + "."
    return text + " If you think this is a mistake, contact the site administrator."


def _join(items: list) -> str:
    return items[0] if len(items) == 1 else ", ".join(items[:-1]) + " and " + items[-1]
