#!/usr/bin/env python3
"""SIH26145 — assemble evaluation/REPORT.md from all artifact metrics.

Usage: python evaluation/make_report.py
"""
import json
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
ART = ROOT / "models/artifacts"


def main() -> None:
    lines = [f"# SIH26145 — Evaluation Report\n",
             f"_generated {datetime.utcnow():%Y-%m-%d %H:%M UTC}_\n"]

    cm = ART / "classical_metrics.json"
    if cm.exists():
        m = json.loads(cm.read_text())
        lines += ["## Classical detector (XGBoost, forward-only features)\n",
                  f"- rows: {m['n_rows']} (train {m['n_train']} / test {m['n_test']}, "
                  "grouped by replay slice — no leakage)",
                  f"- **macro-F1: {m['macro_f1']}**, accuracy: {m['accuracy']}\n",
                  "| attack class | precision | recall | F1 | PR-AUC |",
                  "|---|---|---|---|---|"]
        for cls, v in m["per_class"].items():
            if cls == "BENIGN":
                continue
            lines.append(f"| {cls} | {v['precision']} | {v['recall']} | {v['f1']} "
                         f"| {m['pr_auc_per_class'].get(cls, '—')} |")
        fpr = m.get("fpr_at_recall0.95", {})
        if fpr:
            lines += ["\n**Operating point** tuned for ≥0.95 binary attack recall: "
                      f"FPR = {fpr.get('fpr')} ({fpr.get('false_positives')} false alarms / "
                      f"{fpr.get('total_benign_windows')} benign windows)\n"]
        if m.get("shap_top_features"):
            lines += ["Top SHAP signals: " + ", ".join(f"`{f}`"
                      for f in m["shap_top_features"][:6]) + "\n"]
    else:
        lines.append("## Classical detector\n_not trained yet_\n")

    ae = ART / "ae_metrics.json"
    if ae.exists() and (ART / "lstm_ae_config.json").exists():
        a = json.loads(ae.read_text())
        cfg = json.loads((ART / "lstm_ae_config.json").read_text())
        lines += ["## Novel-threat detector (LSTM-Autoencoder, benign-only training)\n",
                  f"- separation ROC-AUC vs attack windows: **{a.get('auc', '—')}**",
                  f"- threshold (95th pct benign val error): `{cfg['threshold']:.4f}`",
                  f"- candidates: {cfg.get('threshold_candidates')}\n"]
    else:
        lines.append("## LSTM-Autoencoder\n_not trained yet_\n")

    h = ROOT / "data/demo_health.json"
    if not h.exists():
        # try live API
        import urllib.request
        try:
            h_json = urllib.request.urlopen("http://127.0.0.1:8200/health", timeout=2).read()
            Path(ROOT / "data").mkdir(exist_ok=True)
            h.write_text(h_json.decode())
        except Exception:                                   # noqa: BLE001
            pass
    if h.exists():
        health = json.loads(h.read_text())
        lines += ["## Inference latency\n",
                  f"- avg {health.get('avg_latency_ms')} ms/window, "
                  f"p95 {health.get('p95_latency_ms')} ms/window "
                  f"(device: {health.get('device')})\n"]

    out = ROOT / "evaluation/REPORT.md"
    out.write_text("\n".join(lines) + "\n")
    print(f"wrote {out}")


if __name__ == "__main__":
    main()
