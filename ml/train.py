"""Train the classifier and save it. Usage: python -m ml.train [--out models/model.joblib]"""
import argparse
import os

import joblib

from ml.data import generate
from ml.model import Classifier

DEFAULT_PATH = os.path.join("models", "model.joblib")


def train(n: int = 6000, seed: int = 7) -> Classifier:
    requests, labels, _ = generate(n, seed=seed)
    return Classifier().fit(requests, labels)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", default=DEFAULT_PATH)
    parser.add_argument("--samples", type=int, default=6000)
    args = parser.parse_args()
    model = train(args.samples)
    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    joblib.dump(model, args.out)
    print(f"saved {args.out}")


if __name__ == "__main__":
    main()
