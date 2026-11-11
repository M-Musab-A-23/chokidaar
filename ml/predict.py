"""predict(request) -> {score, label, top_features}. The model loads once and is reused."""
import os

import joblib

from ml.train import DEFAULT_PATH, train

DEFAULT_THRESHOLD = 0.5
_model = None


def threshold() -> float:
    """Score at or above which a request is malicious: CHOKIDAAR_THRESHOLD, default 0.5.
    A higher value means fewer false alarms and more missed attacks."""
    raw = os.environ.get("CHOKIDAAR_THRESHOLD", "").strip()
    if not raw:
        return DEFAULT_THRESHOLD
    value = float(raw)
    if not 0.0 < value <= 1.0:
        raise ValueError(f"CHOKIDAAR_THRESHOLD must be above 0 and at most 1, got {raw!r}")
    return value


def load(path: str = None):
    global _model
    path = path or os.environ.get("CHOKIDAAR_MODEL", DEFAULT_PATH)
    _model = joblib.load(path) if os.path.exists(path) else train()
    return _model


def predict(request: dict) -> dict:
    model = _model or load()
    score = float(model.predict_proba([request])[0])
    label = "malicious" if score >= threshold() else "benign"
    return {
        "score": score,
        "label": label,
        "top_features": model.explain(request) if label == "malicious" else [],
    }
