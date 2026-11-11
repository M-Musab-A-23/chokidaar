"""predict(request) -> {score, label, top_features}. The model loads once and is reused."""
import os

import joblib

from ml.train import DEFAULT_PATH, train

THRESHOLD = 0.5
_model = None


def load(path: str = None):
    global _model
    path = path or os.environ.get("CHOKIDAAR_MODEL", DEFAULT_PATH)
    _model = joblib.load(path) if os.path.exists(path) else train()
    return _model


def predict(request: dict) -> dict:
    model = _model or load()
    score = float(model.predict_proba([request])[0])
    label = "malicious" if score >= THRESHOLD else "benign"
    return {
        "score": score,
        "label": label,
        "top_features": model.explain(request) if label == "malicious" else [],
    }
