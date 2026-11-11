from proxy.reason import explain


def test_names_the_attack_and_the_suspicious_parts():
    text = explain(["sql keyword pattern", 'fragment "or 1=1"', 'fragment "\' or"'])
    assert text.startswith("This request was blocked because it looks like SQL injection")
    assert 'Suspicious parts: "or 1=1", "\' or".' in text


def test_short_fragments_are_left_out():
    text = explain(["script tag or handler pattern", 'fragment "scr"', 'fragment "/s"'])
    assert "Suspicious parts" not in text
    text = explain(['fragment "ip"', 'fragment "<script"'])
    assert 'Suspicious parts: "<script".' in text


def test_several_attack_kinds_read_as_a_list():
    text = explain(["path traversal pattern", "shell command pattern"])
    assert "path traversal (" in text and " and command injection (" in text


def test_falls_back_to_a_generic_reason():
    text = explain([])
    assert text.startswith("This request was blocked because it looks like an attack")
    assert "contact the site administrator" in text


def test_flagged_requests_say_flagged_not_blocked():
    text = explain(["sql keyword pattern", 'fragment "or 1=1"'], flagged=True)
    assert text.startswith("This request was flagged because it looks like SQL injection")
    assert "blocked" not in text
    assert 'Suspicious parts: "or 1=1".' in text
    assert "contact the site administrator" not in text
    assert explain([], flagged=True).startswith(
        "This request was flagged because it looks like an attack")


def test_reason_for_a_real_prediction(tmp_path):
    from ml import predict as predict_module

    predict_module.load(str(tmp_path / "missing.joblib"))
    out = predict_module.predict(
        {"method": "GET", "path": "/", "query": "q=<script>alert(1)</script>", "headers": {}, "body": ""}
    )
    assert "cross-site scripting" in explain(out["top_features"])
