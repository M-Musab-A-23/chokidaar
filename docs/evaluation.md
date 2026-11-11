# Evaluation

## How to run

```
python -m ml.evaluate
```

The script trains on 6000 generated requests, tests on 2000 different generated requests, and prints precision, recall, F1, recall per attack type and the time taken per request.

## Results on generated data

| Measure | Value |
| --- | --- |
| Precision | 1.000 |
| Recall | 0.990 |
| F1 | 0.995 |
| False positives | 0 of 1005 normal requests |
| Missed attacks | 10 of 995 |
| Recall: SQL injection | 0.959 |
| Recall: XSS, path traversal, command injection | 1.000 |
| Time per request | median 0.9 ms, 95th percentile 1.1 ms |

## What these numbers mean

The generated data comes from the same templates for training and testing, so these figures are higher than real traffic would give. They show that the pipeline works and that it is fast, not how accurate it is on traffic from the wild. SQL injection is the weakest class because its payloads vary the most.

The classifier is only the second line of defence. The 21 signature rules run first and are tested separately: `tests/attacks/payloads.json` holds malicious and benign payloads for each attack type, and the test suite requires every malicious one to hit a rule of its type and no benign one to hit any rule.

## Held-out checks in the tests

- Unseen SQL injection variants (`HAVING`, `LIKE`, comparison conditions, `WAITFOR DELAY`) are classified as malicious.
- Ordinary phrases that resemble SQL (`having fun in lisbon`, `this or that`, `cats like dogs`) stay benign.
- Double-encoded payloads are caught.
- The 95th percentile time per request stays under 50 ms.

## Public dataset

`ml.data.load_csic()` reads the CSIC 2010 HTTP dataset (normal and anomalous request files). Place the files in `data/raw/` to evaluate on it. Results on that data are the ones to quote for accuracy.
