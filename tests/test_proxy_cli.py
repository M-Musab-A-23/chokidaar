import os
import subprocess
import sys

import pytest

from proxy import cli

UPSTREAM = "http://localhost:3000"


def test_defaults():
    args = cli.parse_args(["--upstream", UPSTREAM])
    assert args.upstream == UPSTREAM
    assert args.port == 8080
    assert args.host == "127.0.0.1"
    assert args.mode == "block"
    assert args.log_db is None


def test_all_options():
    args = cli.parse_args([
        "--upstream", UPSTREAM, "--port", "9000", "--host", "0.0.0.0",
        "--mode", "monitor", "--log-db", "data/requests.db",
    ])
    assert (args.port, args.host, args.mode, args.log_db) == \
        (9000, "0.0.0.0", "monitor", "data/requests.db")


@pytest.mark.parametrize("argv", [
    [],
    ["--upstream", "localhost:3000"],
    ["--upstream", UPSTREAM, "--mode", "learn"],
    ["--upstream", UPSTREAM, "--port", "http"],
    ["--upstream", UPSTREAM, "--port", "0"],
    ["--upstream", UPSTREAM, "--port", "70000"],
])
def test_rejects_bad_arguments(argv, capsys):
    with pytest.raises(SystemExit) as exc:
        cli.parse_args(argv)
    assert exc.value.code == 2
    assert "usage: chokidaar" in capsys.readouterr().err


def test_bad_upstream_names_the_option(capsys):
    with pytest.raises(SystemExit):
        cli.parse_args(["--upstream", "localhost:3000"])
    assert "--upstream must start with http://" in capsys.readouterr().err


def test_sets_env_vars():
    env = {}
    cli.configure_env(cli.parse_args([
        "--upstream", UPSTREAM, "--mode", "monitor", "--log-db", "x.db",
    ]), env)
    assert env == {"UPSTREAM_URL": UPSTREAM, "MODE": "monitor", "LOG_DB": "x.db"}


def test_leaves_log_db_alone_when_not_given():
    env = {"LOG_DB": "kept.db"}
    cli.configure_env(cli.parse_args(["--upstream", UPSTREAM]), env)
    assert env["LOG_DB"] == "kept.db"
    assert env["MODE"] == "block"


def test_main_starts_uvicorn_with_the_app_factory(monkeypatch):
    for name in ("UPSTREAM_URL", "MODE", "LOG_DB"):
        monkeypatch.delenv(name, raising=False)
    calls = []
    monkeypatch.setattr("uvicorn.run", lambda app, **kw: calls.append((app, kw)))

    cli.main(["--upstream", UPSTREAM, "--port", "9000", "--log-db", "x.db"])

    from proxy.app import create_app
    assert calls == [(create_app, {
        "factory": True, "host": "127.0.0.1", "port": 9000,
        "server_header": False, "date_header": False,
    })]
    assert (os.environ["UPSTREAM_URL"], os.environ["MODE"], os.environ["LOG_DB"]) == \
        (UPSTREAM, "block", "x.db")


def test_runs_as_a_module():
    result = subprocess.run([sys.executable, "-m", "proxy.cli", "--help"],
                            capture_output=True, text=True, timeout=60)
    assert result.returncode == 0
    assert "--upstream" in result.stdout


def test_no_bundled_model_when_not_frozen(monkeypatch):
    monkeypatch.delattr(sys, "frozen", raising=False)
    env = {}
    cli.configure_env(cli.parse_args(["--upstream", UPSTREAM]), env)
    assert "CHOKIDAAR_MODEL" not in env


def test_frozen_uses_the_bundled_model(monkeypatch, tmp_path):
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(sys, "_MEIPASS", str(tmp_path), raising=False)
    env = {}
    cli.configure_env(cli.parse_args(["--upstream", UPSTREAM]), env)
    assert env["CHOKIDAAR_MODEL"] == os.path.join(str(tmp_path), "models", "model.joblib")


def test_frozen_keeps_an_explicit_model(monkeypatch, tmp_path):
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(sys, "_MEIPASS", str(tmp_path), raising=False)
    env = {"CHOKIDAAR_MODEL": "my-model.joblib"}
    cli.configure_env(cli.parse_args(["--upstream", UPSTREAM]), env)
    assert env["CHOKIDAAR_MODEL"] == "my-model.joblib"
