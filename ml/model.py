"""The classifier: character n-gram TF-IDF plus hand-made features into logistic regression."""
import numpy as np
from scipy.sparse import csr_matrix, hstack
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import StandardScaler

from ml.features import FEATURE_NAMES, hand_features
from ml.text import request_to_text


class Classifier:
    def __init__(self, c: float = 4.0):
        self.tfidf = TfidfVectorizer(
            analyzer="char", ngram_range=(2, 4), max_features=30000, sublinear_tf=True
        )
        self.scaler = StandardScaler()
        self.clf = LogisticRegression(C=c, max_iter=1000, class_weight="balanced")

    def _matrix(self, requests: list, fit: bool = False):
        texts = [request_to_text(r) for r in requests]
        hand = np.array([hand_features(r) for r in requests])
        if fit:
            text_part = self.tfidf.fit_transform(texts)
            hand_part = self.scaler.fit_transform(hand)
        else:
            text_part = self.tfidf.transform(texts)
            hand_part = self.scaler.transform(hand)
        return hstack([text_part, csr_matrix(hand_part)]).tocsr(), hand_part

    def fit(self, requests: list, labels: list) -> "Classifier":
        X, _ = self._matrix(requests, fit=True)
        self.clf.fit(X, labels)
        return self

    def predict_proba(self, requests: list) -> np.ndarray:
        X, _ = self._matrix(requests)
        return self.clf.predict_proba(X)[:, 1]

    def explain(self, request: dict, top: int = 5) -> list:
        """Names of the features that pushed this request towards 'malicious'."""
        X, hand = self._matrix([request])
        coefs = self.clf.coef_[0]
        n_text = len(coefs) - len(FEATURE_NAMES)
        contributions = X.toarray()[0] * coefs
        ngrams = self.tfidf.get_feature_names_out()
        reasons = []
        for i in np.argsort(contributions[n_text:])[::-1]:
            raw = hand_features(request)[i]
            if contributions[n_text + i] > 0 and raw > 0 and FEATURE_NAMES[i].startswith("hits"):
                reasons.append(FEATURE_NAMES[i].replace("hits: ", "") + " pattern")
        seen = []
        for i in np.argsort(contributions[:n_text])[::-1][: top * 4]:
            if contributions[i] <= 0:
                break
            gram = ngrams[i].strip()
            if gram and not any(gram in s or s in gram for s in seen):
                seen.append(gram)
                reasons.append(f'fragment "{gram}"')
        return reasons[:top]
