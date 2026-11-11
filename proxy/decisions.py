"""What the proxy decided about each request, recorded as one JSON log line."""
import json
import logging
from dataclasses import asdict, dataclass

logger = logging.getLogger("chokidaar.decisions")

# allowed: benign, forwarded.  blocked: malicious, refused with 403 (block mode).
# flagged: malicious, forwarded anyway (monitor mode).
# error:   the classifier failed; forwarded in monitor mode, refused in block mode.
# `rule` is the id of the signature rule that decided, or "" when the classifier did.
ACTIONS = ("allowed", "blocked", "flagged", "error")


@dataclass(frozen=True)
class Decision:
    method: str
    path: str
    query: str
    mode: str
    action: str
    label: str = ""
    score: float = 0.0
    reason: str = ""
    rule: str = ""


def record(decision: Decision) -> None:
    logger.info(json.dumps(asdict(decision)))


def ensure_visible() -> None:
    """Make decision lines show up when nothing else configured logging.

    uvicorn sets up only its own loggers, so without this every INFO record
    from the proxy would be dropped and monitor mode would record nothing.
    """
    root, base = logging.getLogger(), logging.getLogger("chokidaar")
    if base.level == logging.NOTSET:
        base.setLevel(logging.INFO)
    if not root.handlers and not base.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter("%(asctime)s %(name)s %(levelname)s %(message)s"))
        base.addHandler(handler)
