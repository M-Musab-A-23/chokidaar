from ml.text import decode, request_to_text


def test_decode_double_encoded():
    assert decode("%253Cscript%253E") == "<script>"


def test_decode_plain_text_unchanged():
    assert decode("hello world") == "hello world"


def test_request_to_text_lowercases_and_joins():
    text = request_to_text(
        {"method": "GET", "path": "/Search", "query": "q=%27+OR+1%3D1", "headers": {}, "body": ""}
    )
    assert "/search" in text
    assert "' or 1=1" in text


def test_request_to_text_ignores_unrelated_headers():
    text = request_to_text(
        {"method": "GET", "path": "/", "query": "", "headers": {"Accept": "secretvalue"}, "body": ""}
    )
    assert "secretvalue" not in text


def test_request_to_text_handles_missing_fields():
    assert request_to_text({}).strip() == ""
