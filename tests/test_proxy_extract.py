from proxy.extract import MAX_INSPECTED_BODY, to_ml_request


def test_builds_the_classifier_contract():
    out = to_ml_request(
        "post", b"/files/..%2fetc", b"q=%3Cscript%3E",
        [(b"User-Agent", b"curl/8"), (b"content-type", b"text/plain")], b"a=1",
    )
    assert out == {
        "method": "POST",
        "path": "/files/..%2fetc",
        "query": "q=%3Cscript%3E",
        "headers": {"user-agent": "curl/8", "content-type": "text/plain"},
        "body": "a=1",
    }


def test_repeated_headers_are_joined():
    out = to_ml_request("GET", b"/", b"", [(b"cookie", b"a=1"), (b"cookie", b"b=2")], b"")
    assert out["headers"] == {"cookie": "a=1, b=2"}


def test_binary_and_large_bodies_do_not_break_it():
    out = to_ml_request("POST", b"/", b"", [], b"\xff\xfe" + b"x" * (MAX_INSPECTED_BODY * 2))
    assert len(out["body"]) <= MAX_INSPECTED_BODY
    assert out["body"].startswith("�")
