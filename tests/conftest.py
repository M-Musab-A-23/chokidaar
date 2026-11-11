import pytest


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.fixture(autouse=True)
def temporary_log_db(tmp_path, monkeypatch):
    """Every test logs to its own throwaway database, never to logs/."""
    path = tmp_path / "chokidaar-test.db"
    monkeypatch.setenv("LOG_DB", str(path))
    return path
