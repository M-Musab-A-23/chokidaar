"""Run the admin dashboard.

Usage: ADMIN_TOKEN=... python -m dashboard [--port 8081] [--host 127.0.0.1]

The port defaults to DASHBOARD_PORT, then 8081. The log database is LOG_DB,
the same one the proxy writes.
"""
import argparse
import os
import sys

from dashboard.app import token_from_env
from proxy.cli import _port

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8081


def default_port(environ=None) -> int:
    environ = os.environ if environ is None else environ
    value = environ.get("DASHBOARD_PORT", "").strip()
    if not value:
        return DEFAULT_PORT
    try:
        return _port(value)
    except argparse.ArgumentTypeError as exc:
        raise ValueError(f"DASHBOARD_PORT: {exc}") from None


def parse_args(argv=None, environ=None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="python -m dashboard",
        description="Run the Chokidaar admin dashboard (needs ADMIN_TOKEN).",
    )
    try:
        port = default_port(environ)
    except ValueError as exc:
        parser.error(str(exc))
    parser.add_argument("--port", type=_port, default=port,
                        help=f"port to listen on (default DASHBOARD_PORT or {DEFAULT_PORT})")
    parser.add_argument("--host", default=DEFAULT_HOST,
                        help=f"address to listen on (default {DEFAULT_HOST})")
    return parser.parse_args(argv)


def main(argv=None) -> None:
    args = parse_args(argv)
    try:
        token_from_env()
    except RuntimeError as exc:
        sys.exit(f"error: {exc}")
    import uvicorn
    uvicorn.run("dashboard.app:create_app", factory=True, host=args.host, port=args.port,
                server_header=False, date_header=False)


if __name__ == "__main__":
    main()
