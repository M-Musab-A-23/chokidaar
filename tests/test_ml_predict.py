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


@pytest.mark.parametrize("query", [
    "id=5 having 7=7", "name=x' or 'q' like 'q", "id=3' or 9>2 -- ", "id=4 group by 2 having 3=3",
    "id=2'; waitfor delay '0:0:9'--", "id=8 and 6>1", "id=7 or 4 like 4",
])
def test_sql_injection_variants_not_in_training_are_caught(query):
    assert predict(req(query=query))["label"] == "malicious"


@pytest.mark.parametrize("query", [
    "q=having+fun+in+lisbon", "q=this+or+that", "q=5+and+6+items", "q=group+by+size",
    "q=more+than+5", "q=cats+like+dogs",
])
def test_ordinary_words_that_look_like_sql_stay_benign(query):
    assert predict(req(query=query))["label"] == "benign"


def test_threshold_defaults_to_half(monkeypatch):
    monkeypatch.delenv("CHOKIDAAR_THRESHOLD", raising=False)
    assert predict_module.threshold() == 0.5


def test_threshold_can_be_raised(monkeypatch):
    monkeypatch.setenv("CHOKIDAAR_THRESHOLD", "0.99999")
    assert predict(req(query="id=1 or 1=1"))["score"] < 1.0
    assert predict_module.threshold() == 0.99999


@pytest.mark.parametrize("value", ["0", "1.5", "-1", "abc"])
def test_bad_threshold_is_refused(monkeypatch, value):
    monkeypatch.setenv("CHOKIDAAR_THRESHOLD", value)
    with pytest.raises(ValueError):
        predict_module.threshold()
