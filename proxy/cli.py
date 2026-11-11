"""Command-line entry point: parse the options, turn them into the environment
variables the proxy reads, then start uvicorn.

Usage: python -m proxy.cli --upstream http://localhost:3000 [--port 8080]
       [--host 127.0.0.1] [--mode block|monitor] [--log-db PATH]
"""
import argparse
import os
import sys

from proxy.config import DEFAULT_MODE, MODES, Settings

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8080
# Where scripts/build_exe.ps1 puts the trained model inside the executable.
BUNDLED_MODEL = os.path.join("models", "model.joblib")


def _port(value: str) -> int:
    try:
        port = int(value)
    except ValueError:
        raise argparse.ArgumentTypeError(f"not a port number: {value!r}") from None
    if not 1 <= port <= 65535:
        raise argparse.ArgumentTypeError(f"port must be between 1 and 65535, got {port}")
    return port


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="chokidaar",
        description="Run the Chokidaar reverse proxy in front of a web app.",
    )
    parser.add_argument("--upstream", required=True,
                        help="URL of the app to protect, e.g. http://localhost:3000")
    parser.add_argument("--port", type=_port, default=DEFAULT_PORT,
                        help=f"port to listen on (default {DEFAULT_PORT})")
    parser.add_argument("--host", default=DEFAULT_HOST,
                        help=f"address to listen on (default {DEFAULT_HOST})")
    parser.add_argument("--mode", choices=MODES, default=DEFAULT_MODE,
                        help="block malicious requests, or only log them "
                             f"(default {DEFAULT_MODE})")
    parser.add_argument("--log-db", metavar="PATH",
                        help="SQLite file for the request log (default logs/chokidaar.db)")
    return parser


def parse_args(argv=None) -> argparse.Namespace:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        # Same checks the proxy makes on start, reported as a usage error here.
        Settings(upstream_url=args.upstream, mode=args.mode)
    except ValueError as exc:
        parser.error(str(exc).replace("UPSTREAM_URL", "--upstream"))
    return args


def bundled_model_path():
    """The model packed into the executable, or None when not running frozen."""
    if not getattr(sys, "frozen", False):
        return None
    return os.path.join(sys._MEIPASS, BUNDLED_MODEL)


def configure_env(args: argparse.Namespace, environ=None) -> None:
    """Set UPSTREAM_URL, MODE and, when given, LOG_DB for proxy.config and
    proxy.logstore to read. In the executable, CHOKIDAAR_MODEL defaults to the
    bundled model so it is not retrained on every start."""
    environ = os.environ if environ is None else environ
    environ["UPSTREAM_URL"] = args.upstream
    environ["MODE"] = args.mode
    if args.log_db:
        environ["LOG_DB"] = args.log_db
    model = bundled_model_path()
    if model and not environ.get("CHOKIDAAR_MODEL", "").strip():
        environ["CHOKIDAAR_MODEL"] = model


def main(argv=None) -> None:
    args = parse_args(argv)
    configure_env(args)
    # Imported here so --help and argument errors do not wait for the ML stack.
    import uvicorn

    from proxy.app import create_app

    uvicorn.run(create_app, factory=True, host=args.host, port=args.port,
                server_header=False, date_header=False)


if __name__ == "__main__":
    main()
