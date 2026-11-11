import pytest

from ml import predict as predict_module
from ml.predict import predict


@pytest.fixture(autouse=True, scope="module")
def _fresh_model(tmp_path_factory):
    predict_module.load(str(tmp_path_factory.mktemp("m") / "missing.joblib"))


def req(**kw):
    base = {"method": "GET", "path": "/", "query": "", "headers": {}, "body": ""}
    base.update(kw)
    return base


def test_output_contract():
    out = predict(req())
    assert set(out) == {"score", "label", "top_features"}
    assert 0.0 <= out["score"] <= 1.0
    assert out["label"] in {"malicious", "benign"}
    assert isinstance(out["top_features"], list)


@pytest.mark.parametrize("query", [
    "id=1' OR '1'='1", "q=<script>alert(1)</script>", "file=../../../etc/passwd",
    "host=127.0.0.1; cat /etc/passwd", "id=1 UNION SELECT username,password FROM users",
])
def test_attacks_are_malicious(query):
    out = predict(req(query=query))
    assert out["label"] == "malicious"
    assert out["top_features"]


@pytest.mark.parametrize("r", [
    req(path="/products", query="page=2&sort=price"),
    req(path="/search", query="q=red+shoes"),
    req(method="POST", path="/login", body="username=jane&password=Secret123"),
    req(path="/search", query="q=O%27Brien"),
])
def test_normal_requests_are_benign(r):
    out = predict(r)
    assert out["label"] == "benign"
    assert out["top_features"] == []


def test_encoded_attack_is_caught():
    assert predict(req(query="q=%253Cscript%253Ealert(1)%253C/script%253E"))["label"] == "malicious"
