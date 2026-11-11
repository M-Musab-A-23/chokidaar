import pytest

from proxy.config import Settings, from_env


def test_reads_upstream_and_mode():
    s = from_env({"UPSTREAM_URL": "http://app:8000/", "MODE": "Monitor"})
    assert s == Settings(upstream_url="http://app:8000", mode="monitor")


def test_mode_defaults_to_block():
    assert from_env({"UPSTREAM_URL": "http://app:8000"}).mode == "block"
    assert from_env({"UPSTREAM_URL": "http://app:8000", "MODE": ""}).mode == "block"


def test_upstream_is_required():
    with pytest.raises(ValueError, match="UPSTREAM_URL"):
        from_env({})


@pytest.mark.parametrize("env", [
    {"UPSTREAM_URL": "app:8000"},
    {"UPSTREAM_URL": "http://app:8000", "MODE": "learn"},
])
def test_rejects_bad_values(env):
    with pytest.raises(ValueError):
        from_env(env)
