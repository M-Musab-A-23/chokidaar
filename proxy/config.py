"""Proxy settings, read from the environment."""
import os
from dataclasses import dataclass

MODES = ("block", "monitor")
DEFAULT_MODE = "block"


@dataclass(frozen=True)
class Settings:
    upstream_url: str
    mode: str = DEFAULT_MODE

    def __post_init__(self):
        if not self.upstream_url.startswith(("http://", "https://")):
            raise ValueError(
                f"UPSTREAM_URL must start with http:// or https://, got {self.upstream_url!r}"
            )
        if self.mode not in MODES:
            raise ValueError(f"MODE must be one of {', '.join(MODES)}, got {self.mode!r}")


def from_env(environ=None) -> Settings:
    """UPSTREAM_URL is required. MODE is 'block' (default) or 'monitor'."""
    environ = os.environ if environ is None else environ
    upstream = environ.get("UPSTREAM_URL", "").strip()
    if not upstream:
        raise ValueError("UPSTREAM_URL is not set; point it at the app to protect")
    mode = environ.get("MODE", DEFAULT_MODE).strip().lower() or DEFAULT_MODE
    return Settings(upstream_url=upstream.rstrip("/"), mode=mode)
