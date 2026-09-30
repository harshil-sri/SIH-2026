#!/usr/bin/env python3
"""SIH26145 — Alert fusion: combine known-type classifier confidence with
novel-type autoencoder anomaly evidence into ONE threat score.

    score = W_CLF * p_attack_clf + W_AE * ae_flag

where ae_flag is either the classic one-sided sigmoid of (error - threshold) or
a two-sided distance from the benign error mode, chosen by which key the
calibration wrote. The two-sided form matters: rigid floods and portscans
reconstruct BETTER than benign traffic, so a one-sided high-error score can
miss exactly the families whose regularity is the anomaly.

Verdict bands: score >= 0.5 HIGH / >= 0.25 MEDIUM else OK (CRITICAL folds into
HIGH so the demo's clearly-flagged windows still show the family). Weights and
the threshold live in models/artifacts/fusion_config.json (tunable without
retrain — see models/calibrate_fusion.py).
"""
import json
import math
from pathlib import Path

ART = Path("models/artifacts")
# reasonable defaults if nothing has been calibrated yet
DEFAULTS = {"w_clf": 0.65, "w_ae": 0.35, "thr": 0.9, "scale": 0.30,
            "mode": "one-sided",
            # Evidence gating (WS-2): an alert must be carried by at least one
            # DETERMINISTIC detector strand. ML strands (classifier, autoencoder)
            # are evidence/corroboration only and can never raise a verdict
            # alone — the benign soak proved the model strands false-fire on
            # real benign internet traffic, so they never gate.
            "det_strand_min": 0.45,
            "det_alert_min": 0.60,
            "w_det": 0.25,
        }

_cfg: dict | None = None


def load_config(refresh: bool = False) -> dict:
    """Fusion weights, read from disk ONCE and cached.

    This used to stat+read two JSON files on every fuse() call, i.e. on every
    /score request. Under concurrent disk load (a replay writing captures) those
    reads dominated request time — measured ~600ms per window against ~3ms of
    actual model math. Pass refresh=True after retuning weights.
    """
    global _cfg
    if _cfg is not None and not refresh:
        return _cfg
    cfg = dict(DEFAULTS)
    f = ART / "fusion_config.json"
    if f.exists():
        cfg.update(json.loads(f.read_text()))
    elif (ART / "lstm_ae_config.json").exists():
        ae = json.loads((ART / "lstm_ae_config.json").read_text())
        cfg["thr"] = ae["threshold"]
        cfg["scale"] = max(ae.get("val_error_std", 1.0), 1e-6)
    # normalise a typo/freeform mode name rather than silently mis-scoring
    mode = str(cfg.get("mode", "one-sided")).lower()
    cfg["mode"] = "two-sided" if mode in ("two-sided", "2-sided", "both") else "one-sided"
    _cfg = cfg
    return _cfg


def sigmoid(x: float) -> float:
    return 1.0 / (1.0 + math.exp(-x))


def ae_flag(err: float, cfg: dict) -> float:
    if cfg["mode"] == "two-sided":
        # distance from the benign error mode, normalised by its IQR
        med, iqr = cfg["benign_err_median"], cfg["benign_err_iqr"]
        dist = abs(float(err) - med) / max(float(iqr), 1e-9)
        return sigmoid(dist - cfg["dist_thr"])
    # classic one-sided: how far the error clears the benign threshold
    return sigmoid((float(err) - cfg["thr"]) / max(float(cfg["scale"]), 1e-9))


def fuse(p_attack_clf: float, ae_err: float | None = None,
         label_pred: str = "", top_features: list[str] | None = None,
         detector_rows: list[dict] | None = None) -> dict:
    cfg = load_config()
    ae_term = 0.0
    ae_flag_val = None
    if ae_err is not None:
        ae_flag_val = ae_flag(ae_err, cfg)
        ae_term = cfg["w_ae"] * ae_flag_val
    clf_term = cfg["w_clf"] * float(p_attack_clf)
    score = min(1.0, clf_term + ae_term)
    verdict = ("HIGH" if score >= 0.50 else
               "MEDIUM" if score >= 0.25 else "OK")

    # ── per-threat detector strands (WS-2) ──────────────────────────────────
    dets = sorted([r for r in (detector_rows or []) if (r.get("score") or 0) > 0],
                  key=lambda r: -r.get("score", 0))
    strongest_det = dets[0] if dets else None
    alerting_det = (strongest_det if strongest_det
                    and strongest_det["score"] >= cfg["det_alert_min"] else None)
    strand_dets = [r for r in dets if r["score"] >= cfg["det_strand_min"]]
    if strongest_det and strongest_det["score"] >= cfg["det_strand_min"]:
        score = min(1.0, score + cfg["w_det"] * strongest_det["score"])
    if alerting_det:
        # a strong dedicated detector raises the alert even if the generic
        # models were silent — this is the whole point of the six named classes
        score = max(score, alerting_det["score"])

    # Recompute the verdict band from the FINAL score so the label and the
    # number can never disagree. Previously the band was frozen from clf+AE
    # BEFORE the detector term was added, so a detector-boosted window could
    # read "MEDIUM" next to a 0.6 score (and a sub-alert strand could leave a
    # 0.35 window labelled "OK"). The MEDIUM band now actually appears for
    # borderline windows carrying a weak corroborating detector strand.
    verdict = ("HIGH" if score >= 0.50 else
               "MEDIUM" if score >= 0.25 else "OK")

    # ── evidence gating (WS-2): alerts require ≥1 detector strand ───────────
    # ML strands (clf, AE) are evidence/corroboration only; they do NOT gate.
    # No deterministic strand → the alert is ML-only → forced to OK. This is the
    # invariant the 30-min benign soak depends on (benign windows carry no
    # strand, so a model false-positive can never raise a verdict).
    n_det_strands = len(strand_dets)
    gated = None
    if verdict != "OK" and n_det_strands == 0:
        # ML-only evidence: force OK. But DOWN-WEIGHT into the informational
        # band instead of a hard min(0.24, score): the flat clamp pinned nearly
        # every benign window to an identical 0.240 (the weak ML crosses 0.25
        # constantly), which reads as a frozen/broken feed. Multiplying by 0.24
        # keeps the value safely below the 0.25 MEDIUM band (max 0.24) while
        # preserving per-window variation — the zero-FP invariant is unchanged.
        verdict, gated = "OK", "no detector strand — ML evidence only"
        score = round(score * 0.24, 3)

    reasons = []
    if clf_term > 0.05 and label_pred and label_pred != "BENIGN":
        reasons.append(f"classifier matched known pattern: {label_pred} "
                       f"(p={p_attack_clf:.2f})")
        if top_features:
            reasons.append("top signals: " + ", ".join(top_features[:4]))
    if ae_term > 0.05:
        reasons.append(f"sequence anomaly: recon error {ae_err:.3f} "
                       f"({cfg['mode']}, flag {ae_term / cfg['w_ae']:.2f})")
    # surface the top strands: a window can carry multiple detectors (e.g. a
    # port-scanning host that is ALSO pacing like a beacon) and the strongest
    # alone hides the others
    for r in dets[:2]:
        reasons.append(f"{r['threat_class']} detector: {r.get('why') or 'evidence'}")
    if gated:
        reasons.append(f"gate: alert {gated} — {n_det_strands} detector strand(s)")
    out = {"threat_score": round(score, 3), "verdict": verdict,
           "components": {"classifier": round(clf_term, 3),
                          "autoencoder": round(ae_term, 3),
                          "detectors": round((score - min(1.0, clf_term + ae_term))
                                             , 3) if dets else 0.0},
           "reasons": reasons}
    if strongest_det:
        out["detector"] = strongest_det["detector"]
        out["detected_class"] = strongest_det["threat_class"]
    return out


if __name__ == "__main__":
    import sys
    pa = float(sys.argv[1]) if len(sys.argv) > 1 else 0.9
    err = float(sys.argv[2]) if len(sys.argv) > 2 else None
    print(json.dumps(fuse(pa, err, "DoS Hulk"), indent=2))

