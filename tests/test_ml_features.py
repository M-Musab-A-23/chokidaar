from ml.features import FEATURE_NAMES, hand_features


def req(**kw):
    base = {"method": "GET", "path": "/", "query": "", "headers": {}, "body": ""}
    base.update(kw)
    return base


def test_feature_vector_matches_names():
    assert len(hand_features(req())) == len(FEATURE_NAMES)


def test_sql_injection_scores_a_hit():
    f = dict(zip(FEATURE_NAMES, hand_features(req(query="id=1' OR 1=1 --  "))))
    assert f["hits: sql keyword"] >= 1


def test_xss_scores_a_hit():
    f = dict(zip(FEATURE_NAMES, hand_features(req(query="q=<script>alert(1)</script>"))))
    assert f["hits: script tag or handler"] >= 1


def test_traversal_scores_a_hit_even_when_encoded():
    f = dict(zip(FEATURE_NAMES, hand_features(req(query="file=..%2f..%2fetc%2fpasswd"))))
    assert f["hits: path traversal"] >= 1


def test_shell_command_scores_a_hit():
    f = dict(zip(FEATURE_NAMES, hand_features(req(query="host=1.1.1.1; cat /etc/passwd"))))
    assert f["hits: shell command"] >= 1


def test_normal_request_has_no_hits():
    f = dict(zip(FEATURE_NAMES, hand_features(req(path="/products", query="page=2&sort=price"))))
    assert sum(v for k, v in f.items() if k.startswith("hits")) == 0


def test_empty_request_does_not_divide_by_zero():
    assert hand_features({})[2] == 0.0
