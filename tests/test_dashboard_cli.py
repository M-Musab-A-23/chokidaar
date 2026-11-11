import os
import subprocess
import sys

import pytest

from dashboard.__main__ import default_port, parse_args


def test_defaults():
    args = parse_args([], environ={})
    assert (args.host, args.port) == ("127.0.0.1", 8081)


def test_port_comes_from_dashboard_port_and_the_option_wins():
    assert default_port({"DASHBOARD_PORT": "9090"}) == 9090
    assert parse_args([], environ={"DASHBOARD_PORT": "9090"}).port == 9090
    assert parse_args(["--port", "7000"], environ={"DASHBOARD_PORT": "9090"}).port == 7000


@pytest.mark.parametrize("value", ["abc", "0", "70000"])
def test_bad_dashboard_port_is_a_usage_error(value):
    with pytest.raises(SystemExit) as exc:
        parse_args([], environ={"DASHBOARD_PORT": value})
    assert exc.value.code == 2


def test_refuses_to_start_without_admin_token():
    env = {k: v for k, v in os.environ.items() if k != "ADMIN_TOKEN"}
    done = subprocess.run([sys.executable, "-m", "dashboard"], env=env,
                          capture_output=True, text=True, timeout=60)
    assert done.returncode == 1
    assert "ADMIN_TOKEN is not set" in done.stderr
