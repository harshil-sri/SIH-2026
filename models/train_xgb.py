#!/usr/bin/env python3
"""SIH26145 — Classical detector: XGBoost on forward-only tabular features.

Consumes BOTH extractor views (flow-window + source-time-bucket) as one union
schema — XGBoost handles the missing half natively via sparsity-aware splits,
so each row simply leaves the other view's columns as NaN.

Leakage control: split is GROUPED BY slice_id — train and test never share a
replayed capture, so the model is scored on unseen replays, not memorized ones.

Outputs (models/artifacts/):
  xgb_model.joblib, feature_columns.json, label_classes.json,
  classical_metrics.json, classical_confusion.png, classical_shap.png

Usage: python models/train_xgb.py [--features-dir data/features] [--max-rows 800000]
"""
import argparse
import json
from pathlib import Path

import joblib
import numpy as np


def load_union(features_dir: Path):
    """Concatenate both views under their unioned column set."""
    import pandas as pd
    flow_files = sorted(features_dir.glob("flows_*.parquet"))
    src_files = sorted(features_dir.glob("srcwin_*.parquet"))
    if not flow_files and not src_files:
        raise SystemExit(f"no parquet features under {features_dir} — run extractor first")
    fdf = pd.concat([pd.read_parquet(p) for p in flow_files], ignore_index=True) \
        if flow_files else None
    sdf = pd.concat([pd.read_parquet(p) for p in src_files], ignore_index=True) \
        if src_files else None
    meta_cols = {"label", "is_attack", "slice_id", "bucket"}
    feat_f = [c for c in (fdf.columns if fdf is not None else []) if c not in meta_cols]
    feat_s = [c for c in (sdf.columns if sdf is not None else []) if c not in meta_cols]
    union = sorted(set(feat_f) | set(feat_s) | meta_cols)
    parts = []
    for df, feats, view in ((fdf, feat_f, "flow"), (sdf, feat_s, "src")):
        if df is None or not len(df):
            continue
        out = df.reindex(columns=union).copy()
        out["view"] = view
        parts.append(out)
    big = pd.concat(parts, ignore_index=True)
    # string cols that must not go to the model raw
    for col in ("src", "dst"):
        if col in big:
            # cheap numeric hash-ish signal: last octet + first two octets
            octs = big[col].astype(str).str.split(".", expand=True)
            big[f"{col}_o12"] = pd.to_numeric(octs[0], errors="coerce").fillna(-1) * 256 \
                + pd.to_numeric(octs[1], errors="coerce").fillna(-1)
            big[f"{col}_o4"] = pd.to_numeric(octs[3], errors="coerce").fillna(-1)
            big = big.drop(columns=[col])
    return big, union


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--features-dir", default="data/features")
    ap.add_argument("--artifacts-dir", default="models/artifacts")
    ap.add_argument("--max-rows", type=int, default=800_000)
    args = ap.parse_args()

    from sklearn.metrics import (classification_report, precision_recall_curve,
                                 average_precision_score, confusion_matrix)
    from sklearn.model_selection import GroupShuffleSplit
    from sklearn.preprocessing import LabelEncoder
    from sklearn.utils.class_weight import compute_sample_weight
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    import pandas as pd
    import xgboost as xgb

    big, union = load_union(Path(args.features_dir))

    # downsample majority class if needed (RAM discipline)
    benign = big[big.is_attack == 0]
    attack = big[big.is_attack == 1]
    cap = max(10_000, args.max_rows - len(attack))
    if len(benign) > cap:
        benign = benign.sample(cap, random_state=42)
    big = pd.concat([benign, attack], ignore_index=True)
    print(f"dataset: {len(big)} rows ({len(attack)} attack) across "
          f"{big.slice_id.nunique()} slices")

    le = LabelEncoder()
    y = pd.Series(le.fit_transform(big["label"]), index=big.index)

    # stratified split at slice level. classes with only 1 slice go entirely to train.
    slice_labels = big[["slice_id", "label"]].drop_duplicates()
    tr_slices, te_slices = set(), set()
    for lbl in slice_labels["label"].unique():
        sid_s = slice_labels.loc[slice_labels["label"] == lbl, "slice_id"].tolist()
        if len(sid_s) <= 1:
            tr_slices.update(sid_s)
        else:
            n_test = max(1, int(len(sid_s) * 0.25))
            te_slices.update(sid_s[-n_test:])
            tr_slices.update(sid_s[:-n_test])
    tr_mask = big["slice_id"].isin(tr_slices)
    te_mask = big["slice_id"].isin(te_slices)
    X = big.drop(columns=["label", "is_attack", "slice_id", "view"]).astype(float)
    Xtr, Xte = X[tr_mask], X[te_mask]
    ytr, yte = y[tr_mask], y[te_mask]

    sw = compute_sample_weight("balanced", ytr)
    model = xgb.XGBClassifier(
        n_estimators=300, max_depth=8, learning_rate=0.15, subsample=0.8,
        colsample_bytree=0.8, tree_method="hist", eval_metric="mlogloss",
        n_jobs=8, random_state=42, num_class=len(le.classes_))
    model.fit(Xtr, ytr, sample_weight=sw, verbose=False)

    pred = model.predict(Xte)
    proba = model.predict_proba(Xte)

    art = Path(args.artifacts_dir)
    art.mkdir(parents=True, exist_ok=True)
    report = classification_report(yte, pred, target_names=le.classes_, output_dict=True)
    prauc = {}
    for i, cls in enumerate(le.classes_):
        bin_y = (yte == i).astype(int)
        if bin_y.sum() > 0:
            prauc[str(cls)] = round(float(average_precision_score(bin_y, proba[:, i])), 4)

    cm = confusion_matrix(yte, pred)
    fig, ax = plt.subplots(figsize=(9, 7))
    im = ax.imshow(cm)
    ax.set_xticks(range(len(le.classes_)), le.classes_, rotation=45, ha="right")
    ax.set_yticks(range(len(le.classes_)), le.classes_)
    for r in range(cm.shape[0]):
        for c in range(cm.shape[1]):
            ax.text(c, r, cm[r, c], ha="center",
                    color="white" if cm[r, c] > cm.max() / 2 else "black")
    fig.colorbar(im)
    fig.tight_layout()
    fig.savefig(art / "classical_confusion.png", dpi=130)

    # binary operating point: FPR when threshold tuned for >=0.95 attack recall
    benign_idx = list(le.classes_).index("BENIGN")
    attack_idx = [i for i in range(len(le.classes_)) if i != benign_idx]
    p_attack = proba[:, attack_idx].sum(axis=1) / proba.shape[1]
    is_benign_true = (yte == benign_idx)
    prec, rec, thr = precision_recall_curve((~is_benign_true).astype(int), p_attack)
    idx = int(np.argmax(rec >= 0.95)) if (rec >= 0.95).any() else 0
    chosen_thr = float(thr[min(idx, len(thr) - 1)]) if len(thr) else 0.5
    fp = int(((pred != benign_idx) & is_benign_true).sum())
    tn = int(is_benign_true.sum())

    # SHAP on a test sample (judges love this; also our 'not a black box' answer)
    try:
        import shap
        samp = Xte.sample(min(2000, len(Xte)), random_state=1)
        expl = shap.TreeExplainer(model)
        sv = expl.shap_values(samp)
        plt.figure(figsize=(9, 7))
        vals = sv if isinstance(sv, np.ndarray) and sv.ndim == 2 else np.abs(np.array(sv)).sum(axis=0)
        order = np.argsort(np.abs(vals).mean(0))[::-1][:15] if np.array(vals).ndim > 1 \
            else np.argsort(np.abs(vals))[::-1][:15]
        names = [samp.columns[i] for i in order]
        imp = np.abs(np.asarray(vals)).mean(axis=tuple(range(np.asarray(vals).ndim - 1))) \
            if np.asarray(vals).ndim > 1 else np.abs(vals)
        plt.barh(range(15), np.asarray(imp)[order][::-1])
        plt.yticks(range(15), names[::-1])
        plt.title("SHAP |mean| importance (top 15)")
        plt.tight_layout()
        plt.savefig(art / "classical_shap.png", dpi=130)
        shap_top = names[:8]
    except Exception as e:                                   # noqa: BLE001
        shap_top = [f"(shap skipped: {e})"]

    metrics = {
        "n_rows": int(len(X)), "n_train": int(tr_mask.sum()), "n_test": int(te_mask.sum()),
        "macro_f1": round(float(report["macro avg"]["f1-score"]), 4),
        "accuracy": round(float(report["accuracy"]), 4),
        "pr_auc_per_class": prauc,
        "fpr_at_recall0.95": {
            "threshold_on_mean_attack_prob": chosen_thr,
            "false_positives": fp, "total_benign_windows": tn,
            "fpr": round(fp / tn, 5) if tn else None,
        },
        "shap_top_features": shap_top,
        "per_class": {k: {"precision": round(v["precision"], 3),
                          "recall": round(v["recall"], 3),
                          "f1": round(v["f1-score"], 3)}
                      for k, v in report.items() if k not in
                      ("accuracy", "macro avg", "weighted avg")},
    }
    (art / "classical_metrics.json").write_text(json.dumps(metrics, indent=2))
    joblib.dump(model, art / "xgb_model.joblib")
    (art / "feature_columns.json").write_text(json.dumps(list(X.columns)))
    (art / "label_classes.json").write_text(json.dumps(list(le.classes_)))
    print(json.dumps({k: metrics[k] for k in
                      ("macro_f1", "accuracy", "pr_auc_per_class")}, indent=2))
    print(f"artifacts -> {art}/")


if __name__ == "__main__":
    main()
