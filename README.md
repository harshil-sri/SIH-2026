# SIH26145 — AI-Based Detection of Cyber Threats in Unidirectional IP Traffic

Software-emulated data diode (netns + iptables + one-way UDP relay) → forward-only feature extraction →
hybrid ML detection (XGBoost classifier for known attacks + LSTM-Autoencoder for novel threats) → fused
threat score → FastAPI + live dashboard.

## Read these first

| File | Purpose |
|---|---|
| `SIH26145-technical-build-plan.md` | Original problem framing & strategy (base reference) |
| **`PROGRESS.md`** | **Current project state + dated build log — single source of truth** |
| `docs/ARCHITECTURE.md` | System architecture, dataflow, component contracts |
| `docs/DATA_PIPELINE.md` | Datasets, replay/labeling scheme, feature dictionary |
| `docs/HANDOFF.md` | Cold-start guide for a new dev/AI taking over |

## Quick map

```
diode/        netns+iptables setup, one-way UDP relay      (needs sudo)
attacks/      scapy attack generators (custom threats)
replay/       slice -> replay -> capture -> label manifest
extraction/   forward-only features: tabular parquet + seq npz
models/       xgboost/rf baseline; lstm autoencoder
fusion/       classifier confidence x recon error -> threat score
serving/      fastapi inference service
dashboard/    live visualization + alert feed
evaluation/   metrics, latency bench
datasets/raw/ downloads (gitignored) — see scripts/download_datasets.sh
data/         intermediate artifacts (gitignored)
```

## Setup

```bash
sudo bash scripts/bootstrap_sudo.sh   # once: apt tooling + scoped sudoers
bash scripts/setup_venv.sh            # python env (.venv/)
bash scripts/download_datasets.sh     # resumable dataset fetch (~50GB)
```
