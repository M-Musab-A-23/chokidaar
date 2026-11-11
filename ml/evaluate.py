"""Held-out evaluation: precision, recall, F1, per-attack recall and latency.
Usage: python -m ml.evaluate"""
import statistics
import time

from ml.data import generate
from ml.model import Classifier


def metrics(labels: list, predicted: list) -> dict:
    tp = sum(1 for y, p in zip(labels, predicted) if y and p)
    fp = sum(1 for y, p in zip(labels, predicted) if not y and p)
    fn = sum(1 for y, p in zip(labels, predicted) if y and not p)
    tn = sum(1 for y, p in zip(labels, predicted) if not y and not p)
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {"tp": tp, "fp": fp, "fn": fn, "tn": tn,
            "precision": precision, "recall": recall, "f1": f1}


def evaluate(train_n: int = 6000, test_n: int = 2000, threshold: float = 0.5) -> dict:
    x_train, y_train, _ = generate(train_n, seed=7)
    x_test, y_test, kinds = generate(test_n, seed=99)
    model = Classifier().fit(x_train, y_train)
    scores = model.predict_proba(x_test)
    predicted = [int(s >= threshold) for s in scores]
    result = metrics(y_test, predicted)
    per_kind = {}
    for kind in sorted(set(k for k in kinds if k)):
        idx = [i for i, k in enumerate(kinds) if k == kind]
        per_kind[kind] = sum(predicted[i] for i in idx) / len(idx)
    times = []
    for r in x_test[:300]:
        start = time.perf_counter()
        model.predict_proba([r])
        times.append((time.perf_counter() - start) * 1000)
    result["recall_by_attack"] = per_kind
    result["latency_ms_median"] = statistics.median(times)
    result["latency_ms_p95"] = sorted(times)[int(len(times) * 0.95)]
    return result


def main() -> None:
    result = evaluate()
    for key in ("precision", "recall", "f1"):
        print(f"{key:10s} {result[key]:.3f}")
    print(f"confusion  tp={result['tp']} fp={result['fp']} fn={result['fn']} tn={result['tn']}")
    for kind, value in result["recall_by_attack"].items():
        print(f"recall {kind:10s} {value:.3f}")
    print(f"latency    median {result['latency_ms_median']:.1f} ms, p95 {result['latency_ms_p95']:.1f} ms")


if __name__ == "__main__":
    main()
