"""Loading and splitting the CSIC 2010 HTTP dataset.

The dataset has three files: normalTrafficTraining.txt and normalTrafficTest.txt (all
normal) and anomalousTrafficTest.txt (all attacks). The attacks are split in half with a
fixed seed: one half joins the normal training file as the training set, the other half
joins the normal test file as the test set."""
import os
import random

from ml.data import load_csic

FILES = ("normalTrafficTraining.txt", "normalTrafficTest.txt", "anomalousTrafficTest.txt")
DEFAULT_DIR = os.path.join("data", "raw")


def load(directory: str = DEFAULT_DIR) -> tuple:
    paths = [os.path.join(directory, f) for f in FILES]
    missing = [p for p in paths if not os.path.exists(p)]
    if missing:
        raise FileNotFoundError("missing: " + ", ".join(missing))
    normal_train, _ = load_csic(paths[0], 0)
    normal_test, _ = load_csic(paths[1], 0)
    attacks, _ = load_csic(paths[2], 1)
    return normal_train, normal_test, attacks


def split(normal_train: list, normal_test: list, attacks: list, seed: int = 7) -> tuple:
    """Return x_train, y_train, x_test, y_test."""
    rng = random.Random(seed)
    attacks = attacks[:]
    rng.shuffle(attacks)
    half = len(attacks) // 2
    x_train = normal_train + attacks[:half]
    y_train = [0] * len(normal_train) + [1] * half
    x_test = normal_test + attacks[half:]
    y_test = [0] * len(normal_test) + [1] * (len(attacks) - half)
    return x_train, y_train, x_test, y_test


def without_headers(requests: list) -> list:
    return [dict(r, headers={}) for r in requests]
