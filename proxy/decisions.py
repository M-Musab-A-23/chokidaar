"""What the proxy decided about each request, recorded as one JSON log line."""
import json
import logging
from dataclasses import asdict, dataclass

logger = logging.getLogger("chokidaar.decisions")

# allowed: benign, forwarded.  blocked: malicious, refused with 403 (block mode).
# flagged: malicious, forwarded anyway (monitor mode).
# error:   the classifier failed; forwarded in monitor mode, refused in block mode.
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


def record(decision: Decision) -> None:
    logger.info(json.dumps(asdict(decision)))
