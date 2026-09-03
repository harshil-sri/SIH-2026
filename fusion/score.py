#!/usr/bin/env python3
"""SIH26145 — Alert fusion: combine known-type classifier confidence with
novel-type autoencoder anomaly evidence into ONE threat score.

    score = W_CLF * p_attack_clf + W_AE * sigmoid((ae_err - thr) / scale)

Verdict bands: score >= 0.75 CRITICAL / 0.5 HIGH / 0.25 MEDIUM else OK.
Weights live in models/artifacts/fusion_config.json (tunable without retrain).
"""
import json
import math
from pathlib import Path

ART = Path("models/artifacts")
DEFAULTS = {"w_clf": 0.6, "w_ae": 0.4, "thr": 0.0, "scale": 1.0}


def load_config() -> dict:
    cfg = dict(DEFAULTS)
    f = ART / "fusion_config.json"
    if f.exists():
        cfg.update(json.loads(f.read_text()))
    elif (ART / "lstm_ae_config.json").exists():
        ae = json.loads((ART / "lstm_ae_config.json").read_text())
        cfg["thr"] = ae["threshold"]
        cfg["scale"] = max(ae.get("val_error_std", 1.0), 1e-6)
    return cfg


def sigmoid(x: float) -> float:
    return 1.0 / (1.0 + math.exp(-x))


def fuse(p_attack_clf: float, ae_err: float | None = None,
         label_pred: str = "", top_features: list[str] | None = None) -> dict:
    cfg = load_config()
    ae_term = 0.0
    if ae_err is not None:
        ae_term = cfg["w_ae"] * sigmoid((float(ae_err) - cfg["thr"]) / cfg["scale"])
    clf_term = cfg["w_clf"] * float(p_attack_clf)
    score = min(1.0, clf_term + ae_term)
    verdict = ("CRITICAL" if score >= 0.75 else
               "HIGH" if score >= 0.50 else
               "MEDIUM" if score >= 0.25 else "OK")
    reasons = []
    if clf_term > 0.05 and label_pred and label_pred != "BENIGN":
        reasons.append(f"classifier matched known pattern: {label_pred} "
                       f"(p={p_attack_clf:.2f})")
        if top_features:
            reasons.append("top signals: " + ", ".join(top_features[:4]))
    if ae_term > 0.05:
        reasons.append(f"sequence anomaly: recon error {ae_err:.3f} vs threshold "
                       f"{cfg['thr']:.3f}")
    return {"threat_score": round(score, 3), "verdict": verdict,
            "components": {"classifier": round(clf_term, 3),
                           "autoencoder": round(ae_term, 3)},
            "reasons": reasons}


if __name__ == "__main__":
    import sys
    pa = float(sys.argv[1]) if len(sys.argv) > 1 else 0.9
    err = float(sys.argv[2]) if len(sys.argv) > 2 else None
    print(json.dumps(fuse(pa, err, "DoS Hulk"), indent=2))
