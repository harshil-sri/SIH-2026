# SIH26145 — Evaluation Report

_generated 2026-09-03 18:48 UTC_

## Classical detector (XGBoost, forward-only features)

- rows: 90178 (train 69995 / test 20183, grouped by replay slice — no leakage)
- **macro-F1: 0.2513**, accuracy: 0.6048

| attack class | precision | recall | F1 | PR-AUC |
|---|---|---|---|---|
| Bot | 0.0 | 0.0 | 0.0 | — |
| DoS slowloris | 0.0 | 0.0 | 0.0 | — |

**Operating point** tuned for ≥0.95 binary attack recall: FPR = 0.39518 (7976 false alarms / 20183 benign windows)

Top SHAP signals: `(shap skipped: shape mismatch: objects cannot be broadcast to a single shape.  Mismatch is between 'width' with shape (3,) and 'y' with shape (15,).)`

## Novel-threat detector (LSTM-Autoencoder, benign-only training)

- separation ROC-AUC vs attack windows: **0.4499**
- threshold (95th pct benign val error): `0.9750`
- candidates: {'0.9': 0.8718398392200472, '0.95': 0.9750239580869674, '0.97': 1.0551972734928132, '0.99': 1.2486297726631148, '0.995': 1.39159108698368, '0.999': 1.7836725646257392}

