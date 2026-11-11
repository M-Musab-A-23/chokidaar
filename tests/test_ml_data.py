from ml.data import generate, load_csic


def test_generate_is_deterministic():
    assert generate(50, seed=1) == generate(50, seed=1)


def test_generate_mixes_both_labels():
    _, labels, _ = generate(400)
    assert 0.3 < sum(labels) / len(labels) < 0.7


def test_generate_requests_have_all_fields():
    requests, _, _ = generate(20)
    for r in requests:
        assert set(r) == {"method", "path", "query", "headers", "body"}


def test_malicious_kinds_are_labelled():
    _, labels, kinds = generate(300)
    assert all((k != "") == bool(y) for k, y in zip(kinds, labels))


def test_load_csic_parses_get_and_post(tmp_path):
    raw = (
        "GET http://localhost:8080/tienda1/index.jsp?id=2 HTTP/1.1\r\nUser-Agent: Mozilla\r\n"
        "Host: localhost:8080\r\n\r\n"
        "POST http://localhost:8080/tienda1/login.jsp HTTP/1.1\r\nContent-Length: 17\r\n\r\n"
        "user=a&password=b\r\n\r\n"
    )
    f = tmp_path / "csic.txt"
    f.write_bytes(raw.encode())
    requests, labels = load_csic(str(f), 0)
    assert [r["method"] for r in requests] == ["GET", "POST"]
    assert requests[0]["query"] == "id=2"
    assert requests[1]["body"] == "user=a&password=b"
    assert labels == [0, 0]
