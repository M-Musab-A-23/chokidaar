# ml

Feature extraction, training and prediction for the request classifier.

```
python -m ml.train       # trains on the bundled samples, writes models/model.joblib
python -m ml.evaluate    # precision, recall, F1 and latency on a held-out split
```

Trained model files and raw datasets are not committed.

## Interface

```python
from ml.predict import predict

predict({"method": "GET", "path": "/search", "query": "q=' OR 1=1 --", "headers": {}, "body": ""})
# {"score": 0.99, "label": "malicious", "top_features": ["sql keyword pattern", 'fragment "or 1=1"']}
```

`score` is between 0 and 1, and a request at or above 0.5 is labelled `malicious`. `top_features` is only filled for malicious requests and is shown to the user as the reason for the block. The model is loaded from `models/model.joblib` (or the path in `CHOKIDAAR_MODEL`); if the file is missing it is trained on the bundled samples.

## How it works

1. `ml/text.py` joins the method, path, query, a few headers and the body, URL-decodes up to twice and lower-cases.
2. `ml/features.py` adds numeric features: length, special characters, percent-encoding, digits and hits for SQL, script, traversal and shell patterns.
3. `ml/model.py` combines character 2-4-grams (TF-IDF) with those features in a logistic regression.

## Data and results

`ml/data.py` generates a seeded mix of normal and malicious requests (SQL injection, XSS, path traversal, command injection; with URL encoding, case changes and comment padding). `load_csic()` reads the CSIC 2010 HTTP dataset when it is downloaded to `data/raw/`.

On generated data the model scores above 0.99 F1 with about 1 ms per request. This is optimistic because the test split comes from the same templates as the training split; the CSIC 2010 numbers are the ones to report.
