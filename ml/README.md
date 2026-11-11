# ml

Feature extraction, training and prediction for the request classifier.

```
python -m ml.train       # trains on the bundled samples, writes models/model.joblib
python -m ml.evaluate    # precision, recall, F1 and latency on a held-out split
```

Trained model files and raw datasets are not committed.
