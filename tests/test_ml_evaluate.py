from ml.evaluate import evaluate, metrics


def test_metrics_perfect():
    m = metrics([1, 0, 1, 0], [1, 0, 1, 0])
    assert m["precision"] == m["recall"] == m["f1"] == 1.0


def test_metrics_counts():
    m = metrics([1, 1, 0, 0], [1, 0, 1, 0])
    assert (m["tp"], m["fn"], m["fp"], m["tn"]) == (1, 1, 1, 1)
    assert m["f1"] == 0.5


def test_metrics_no_positives_does_not_crash():
    assert metrics([0, 0], [0, 0])["f1"] == 0.0


def test_model_meets_targets():
    r = evaluate(train_n=3000, test_n=800)
    assert r["recall"] >= 0.90
    assert r["precision"] >= 0.90
    assert r["latency_ms_p95"] < 50
