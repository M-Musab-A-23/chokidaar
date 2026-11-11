"""Train the classifier and save it. Usage: python -m ml.train [--out models/model.joblib]"""
import argparse
import os

import joblib

from ml.csic import DEFAULT_DIR as CSIC_DIR, load as load_csic_files, split as csic_split
from ml.data import generate
from ml.model import Classifier

DEFAULT_PATH = os.path.join("models", "model.joblib")


def train(n: int = 6000, seed: int = 7, csic_dir: str = None) -> Classifier:
    """Train on generated requests, plus the training part of the CSIC 2010 dataset when
    `csic_dir` is given (the test part is never used)."""
    requests, labels, _ = generate(n, seed=seed)
    if csic_dir:
        x_train, y_train, _, _ = csic_split(*load_csic_files(csic_dir))
        requests, labels = requests + x_train, labels + y_train
    return Classifier().fit(requests, labels)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", default=DEFAULT_PATH)
    parser.add_argument("--samples", type=int, default=6000)
    parser.add_argument("--csic", nargs="?", const=CSIC_DIR, default=None, metavar="DIR",
                        help="also train on the CSIC 2010 dataset (default folder data/raw)")
    args = parser.parse_args()
    model = train(args.samples, csic_dir=args.csic)
    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    joblib.dump(model, args.out)
    print(f"saved {args.out}")


if __name__ == "__main__":
    main()
