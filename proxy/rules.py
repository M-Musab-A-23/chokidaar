"""Signature rules that catch well-known attacks before the classifier runs.

Each rule is a regular expression for one attack type. Every part of the
request (method, path, query, each header value, body) is checked in every
form it can take after URL decoding (up to three rounds, so double-encoded
payloads are exposed) and after HTML entity decoding. A hit is reported with
the rule id and a sentence a site visitor or admin can understand.
"""
import html
import re
from dataclasses import dataclass
from urllib.parse import unquote_plus

DECODE_ROUNDS = 3
# Only this much of the matched text is quoted back in the reason.
MAX_QUOTED = 60

ATTACK_NAMES = {
    "sql_injection": "SQL injection (an attempt to run database commands)",
    "xss": "cross-site scripting (an attempt to run scripts in the browser)",
    "path_traversal": "path traversal (an attempt to read files outside the website)",
    "command_injection": "command injection (an attempt to run commands on the server)",
}

# Shell commands an attacker typically chains onto a parameter to see if it runs.
_COMMANDS = (
    r"(?:cat|ls|id|whoami|uname|pwd|hostname|ifconfig|ipconfig|netstat|wget|curl|"
    r"nc|ncat|netcat|bash|sh|zsh|python[23]?|perl|ruby|php|ping|nslookup|rm|chmod|"
    r"echo|powershell|cmd(?:\.exe)?|net\s+user|sleep)"
)


@dataclass(frozen=True)
class Rule:
    id: str
    attack_type: str
    regex: str
    description: str

    def __post_init__(self):
        if self.attack_type not in ATTACK_NAMES:
            raise ValueError(f"unknown attack type {self.attack_type!r} in rule {self.id}")
        object.__setattr__(self, "_compiled", re.compile(self.regex, re.IGNORECASE))

    def search(self, text: str):
        return self._compiled.search(text)


@dataclass(frozen=True)
class Match:
    rule_id: str
    attack_type: str
    location: str
    matched: str
    reason: str


RULES = [
    # --- SQL injection ---
    Rule("sqli-union-select", "sql_injection",
         r"\bunion\b[\s/*()]+(?:all[\s/*()]+|distinct[\s/*()]+)?select\b",
         "a UNION SELECT that would read data from other tables"),
    Rule("sqli-tautology", "sql_injection",
         r"\b(?:or|and)\b[\s(]+(['\"]?)(\w+)\1\s*(?:=|\blike\b)\s*\(?\s*\1\2\1?(?!\w)",
         "an always-true condition such as OR 1=1 that would bypass a check"),
    Rule("sqli-quote-comment", "sql_injection",
         r"'\s*\)*\s*(?:--|#|/\*)",
         "a quote followed by an SQL comment that would cut off the rest of a query"),
    Rule("sqli-stacked-query", "sql_injection",
         r";\s*(?:drop\s+(?:table|database)|delete\s+from|insert\s+into|update\s+\w+\s+set\b|"
         r"truncate\s+table|alter\s+table|create\s+(?:table|user)|exec(?:ute)?\s+(?:xp_|sp_)|"
         r"shutdown\b|declare\s+@)",
         "a second SQL statement appended to change or destroy data"),
    Rule("sqli-time-delay", "sql_injection",
         r"\b(?:sleep\s*\(\s*\d+\s*\)|pg_sleep\s*\(\s*\d+|benchmark\s*\(\s*\d+\s*,|"
         r"waitfor\s+delay\s+')",
         "a deliberate database delay used to probe for injection"),
    Rule("sqli-schema-probe", "sql_injection",
         r"\binformation_schema\b|\bsqlite_master\b|\bpg_catalog\b|@@version\b|"
         r"\bsys\.(?:tables|objects|columns)\b|\bload_file\s*\(|\binto\s+(?:out|dump)file\b|"
         r"\b(?:extractvalue|updatexml)\s*\(",
         "a reference to database internals or files that a normal request never needs"),

    # --- Cross-site scripting ---
    Rule("xss-script-tag", "xss", r"<\s*/?\s*script\b",
         "a <script> tag"),
    Rule("xss-event-handler", "xss", r"<[a-z!][^>]*?[\s/\"'](on[a-z]{3,})\s*=",
         "an HTML tag with an event handler such as onerror or onload"),
    Rule("xss-script-url", "xss",
         r"\b(?:javascript|vbscript|livescript)\s*:[^\s]*?[(`]|\bdata\s*:\s*text/html\b",
         "a javascript: or data: link that runs code when opened"),
    Rule("xss-embedding-tag", "xss", r"<\s*(?:iframe|frame|frameset|object|embed|applet|base)\b",
         "a tag that loads another page or plugin into this one"),
    Rule("xss-script-call", "xss",
         r"\b(?:alert|prompt|confirm)\s*[(`]\s*(?:\d|['\"`]|document\b|window\b|this\b)|"
         r"\bdocument\s*\.\s*(?:cookie|write|domain)\b|\bstring\s*\.\s*fromcharcode\s*\(|"
         r"\beval\s*\(\s*(?:atob|unescape|string|['\"])",
         "JavaScript that reads cookies or runs injected code"),

    # --- Path traversal ---
    Rule("traversal-dot-dot", "path_traversal", r"(?:^|[\\/=\s'\":;,&?])\.\.[\\/]",
         "../ sequences that climb out of the website's folder"),
    Rule("traversal-overlong", "path_traversal", r"%(?:c0%(?:ae|af)|c1%(?:9c|1c)|e0%80%ae)",
         "an invalid character encoding used to disguise ../"),
    Rule("traversal-system-file", "path_traversal",
         r"/etc/(?:passwd|shadow|group|sudoers)\b|/proc/self/|\b(?:boot|win)\.ini\b|"
         r"\\windows\\(?:system32|win\.ini)|/\.(?:htpasswd|htaccess|ssh/)|\bweb\.config\b",
         "the name of an operating system or server configuration file"),
    Rule("traversal-null-byte", "path_traversal", r"\.[a-z0-9]{1,5}\x00",
         "a null byte used to cut off a file name"),
    Rule("traversal-file-wrapper", "path_traversal",
         r"\bfile:/{2,3}|\bphp://(?:filter|input)|\b(?:zip|phar|expect)://",
         "a file:// or php:// address that reads files on the server"),

    # --- Command injection ---
    Rule("cmdi-chained-command", "command_injection",
         r"(?:;|&&?|\|\|?)\s*(?:/(?:usr/)?bin/)?" + _COMMANDS +
         r"\b(?!\s*=)(?!\.\w)(?=\s|$|[;|&<>`)'\"/-])",
         "a shell command chained on with ;, | or &"),
    Rule("cmdi-newline-command", "command_injection",
         r"[\r\n]\s*(?:/(?:usr/)?bin/)?" + _COMMANDS + r"\b(?!\s*=)\s*(?:$|-|/|\.\.|[;|&]|https?:)",
         "a shell command on a new line"),
    Rule("cmdi-substitution", "command_injection",
         r"\$\(\s*(?:/(?:usr/)?bin/)?" + _COMMANDS + r"\b|`\s*(?:/(?:usr/)?bin/)?" + _COMMANDS +
         r"\b[^`]*`",
         "a $( ) or backtick command substitution"),
    Rule("cmdi-shellshock", "command_injection", r"\(\s*\)\s*\{\s*:?\s*;?\s*\}\s*;",
         "the Shellshock bash function trick"),
    Rule("cmdi-shell-plumbing", "command_injection",
         r"\$\{?ifs\}?|/dev/(?:tcp|udp)/|\bnc(?:at)?\s+(?:-\w+\s+)*-[ec]\s|"
         r"/bin/(?:ba|z)?sh\b|\bcmd(?:\.exe)?\s+/c\b|\bpowershell(?:\.exe)?\s+-(?:e|enc|c|command)\b",
         "a shell, reverse connection or shell variable trick"),
]


def variants(value: str) -> list:
    """The value as sent, after each round of URL decoding, and with HTML entities decoded."""
    forms = [value]
    for _ in range(DECODE_ROUNDS):
        decoded = unquote_plus(forms[-1])
        if decoded == forms[-1]:
            break
        forms.append(decoded)
    unescaped = html.unescape(forms[-1])
    if unescaped != forms[-1]:
        forms.append(unescaped)
    return forms


def _parts(request: dict):
    yield "method", str(request.get("method") or "")
    yield "path", str(request.get("path") or "")
    yield "query string", str(request.get("query") or "")
    for name, value in (request.get("headers") or {}).items():
        yield f"{name} header", str(value)
    yield "body", str(request.get("body") or "")


def _quote(text: str) -> str:
    text = " ".join(text.split())
    if len(text) > MAX_QUOTED:
        text = text[:MAX_QUOTED] + "..."
    return f'"{text}"'


def reason_for(rule: Rule, location: str, matched: str) -> str:
    return (
        f"This request was blocked because it looks like {ATTACK_NAMES[rule.attack_type]}: "
        f"the {location} contains {rule.description}. Suspicious part: {_quote(matched)}. "
        "If you think this is a mistake, contact the site administrator."
    )


def _matches(request: dict, rules: list):
    forms = [(location, variants(value)) for location, value in _parts(request) if value]
    for rule in rules:
        for location, texts in forms:
            hit = next((m for m in map(rule.search, texts) if m), None)
            if hit:
                matched = hit.group(0)
                yield Match(rule.id, rule.attack_type, location, matched,
                            reason_for(rule, location, matched))
                break


def scan(request: dict, rules: list = None) -> list:
    """Every rule that matches the request, at most once per rule, in rule order.

    `request` has the classifier's shape: method, path, query, headers, body.
    """
    return list(_matches(request, RULES if rules is None else rules))


def first_match(request: dict, rules: list = None):
    """The first matching rule, or None. Stops at the first hit."""
    return next(_matches(request, RULES if rules is None else rules), None)
