"""Evaluate on the CSIC 2010 HTTP dataset. Usage: python -m ml.evaluate_csic [--dir data/raw]

Compares the signature rules, a classifier trained only on generated data, a classifier
trained on the CSIC training split, and one trained on both, then shows how the threshold
trades missed attacks against false alarms."""
import argparse
import time

from ml.csic import DEFAULT_DIR, load, split, without_headers
from ml.data import generate
from ml.evaluate import metrics
from ml.model import Classifier
from proxy.rules import first_match

THRESHOLDS = (0.5, 0.6, 0.7, 0.8, 0.9, 0.95)


def row(name: str, y_true: list, y_pred: list) -> str:
    m = metrics(y_true, y_pred)
    negatives = m["fp"] + m["tn"]
    fpr = m["fp"] / negatives if negatives else 0.0
    return (f"{name:<46s} {m['precision']:.3f}  {m['recall']:.3f}  {m['f1']:.3f}  "
            f"{fpr:.4f}  {m['fp']:>6d} {m['fn']:>6d}")


def label(scores, threshold: float = 0.5) -> list:
    return [int(s >= threshold) for s in scores]


def either(a: list, b: list) -> list:
    return [int(x or y) for x, y in zip(a, b)]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dir", default=DEFAULT_DIR)
    args = parser.parse_args()
    x_train, y_train, x_test, y_test = split(*load(args.dir))
    print(f"train: {len(x_train)} requests ({sum(y_train)} attacks); "
          f"test: {len(x_test)} requests ({sum(y_test)} attacks)\n")

    rules = [int(first_match(r) is not None) for r in x_test]
    gen_x, gen_y, _ = generate(6000, seed=7)
    generated = Classifier().fit(gen_x, gen_y)
    csic = Classifier().fit(x_train, y_train)
    both = Classifier().fit(gen_x + x_train, gen_y + y_train)
    scores = {"generated": generated.predict_proba(x_test), "csic": csic.predict_proba(x_test),
              "both": both.predict_proba(x_test)}

    header = f"{'method':<46s} prec   recall f1     fpr     fp     fn"
    print(header)
    print(row("signature rules only", y_test, rules))
    print(row("classifier, generated data only", y_test, label(scores["generated"])))
    print(row("classifier, CSIC training split", y_test, label(scores["csic"])))
    print(row("classifier, generated data + CSIC training split", y_test, label(scores["both"])))
    print(row("rules + classifier (generated + CSIC)", y_test,
              either(rules, label(scores["both"]))))

    print("\nthreshold for the classifier trained on generated data + CSIC, with the rules:")
    print(header)
    for t in THRESHOLDS:
        print(row(f"threshold {t}", y_test, either(rules, label(scores["both"], t))))

    bare = Classifier().fit(without_headers(gen_x + x_train), gen_y + y_train)
    bare_scores = bare.predict_proba(without_headers(x_test))
    print("\nwithout request headers (method, path, query and body only):")
    print(header)
    print(row("classifier, generated data + CSIC training split", y_test, label(bare_scores)))

    times = []
    for r in x_test[:300]:
        start = time.perf_counter()
        both.predict_proba([r])
        times.append((time.perf_counter() - start) * 1000)
    times.sort()
    print(f"\nclassifier time per request: median {times[len(times) // 2]:.1f} ms, "
          f"p95 {times[int(len(times) * 0.95)]:.1f} ms")


if __name__ == "__main__":
    main()
