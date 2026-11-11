import pytest

from ml.csic import FILES, load, split, without_headers


def write(path, requests):
    path.write_bytes(("\r\n\r\n".join(requests) + "\r\n\r\n").encode())


@pytest.fixture
def folder(tmp_path):
    get = "GET http://localhost:8080/tienda1/index.jsp?id={} HTTP/1.1\r\nHost: localhost:8080\r\nCookie: JSESSIONID=1"
    write(tmp_path / FILES[0], [get.format(i) for i in range(6)])
    write(tmp_path / FILES[1], [get.format(i) for i in range(4)])
    write(tmp_path / FILES[2], [get.format(f"'{i}") for i in range(10)])
    return tmp_path


def test_load_reads_the_three_files(folder):
    normal_train, normal_test, attacks = load(str(folder))
    assert (len(normal_train), len(normal_test), len(attacks)) == (6, 4, 10)


def test_load_names_the_missing_files(tmp_path):
    with pytest.raises(FileNotFoundError, match="normalTrafficTraining"):
        load(str(tmp_path))


def test_split_halves_the_attacks(folder):
    x_train, y_train, x_test, y_test = split(*load(str(folder)))
    assert (sum(y_train), sum(y_test)) == (5, 5)
    assert (len(x_train), len(x_test)) == (11, 9)


def test_split_is_repeatable_and_keeps_halves_apart(folder):
    parts = load(str(folder))
    a, b = split(*parts), split(*parts)
    assert a == b
    train_attacks = {r["query"] for r, y in zip(a[0], a[1]) if y}
    test_attacks = {r["query"] for r, y in zip(a[2], a[3]) if y}
    assert not train_attacks & test_attacks


def test_without_headers_keeps_the_rest():
    r = {"method": "GET", "path": "/", "query": "a=1", "headers": {"Cookie": "x"}, "body": ""}
    assert without_headers([r]) == [dict(r, headers={})]
