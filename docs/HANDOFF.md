# SIH26145 — Handoff Document

> For the AI model that continues: this document gives you the full context
> to resume work cold. Read PROGRESS.md first, then this.

## Project State

Working prototype built. **Everything is ready EXCEPT training the two ML models**
— Harshal wants to launch those himself.

### What exists

```
SIH-2026/
├── datasets/raw/                          # 50 GB: Friday-*, Monday-*, ... pcaps + CSVs
├── replay/slices/                         # 6 slice pcaps (benign ×4, bot, dos)
├── data/
│   ├── features/                          # ✅ Extracted features (parquet + npz)
│   ├── captures/                          # ✅ Replay captures (diode-filtered)
│   ├── windows_pcap.json                  # ✅ Attack windows (pcap-verified)
│   └── pcap_starts.json                   # ✅ Cached pcap start timestamps
├── models/
│   ├── train_xgb.py                       # ✅ Ready; reads data/features/*.parquet
│   ├── lstm_ae.py                         # ✅ Ready; reads data/features/*.npz
│   └── artifacts/                         # (created by training)
├── diode/                                 # ✅ Verified: setup, relay, verify, teardown
├── extraction/
│   ├── extract_features.py                # ✅ Forward-only extractor
│   └── batch_extract.py                   # ✅ Batch runner
├── serving/app.py                         # ✅ FastAPI service
├── dashboard/app.py                       # ✅ Streamlit dashboard
├── fusion/score.py                        # ✅ Alert fusion
├── attacks/generate.py                    # ✅ Custom attack generators
├── scripts/
│   ├── download_aria.sh                   # ✅ aria2c-based downloader
│   ├── bootstrap_sudo.sh                  # ✅ Sudo setup (already run)
│   └── live_demo.sh                       # ✅ Live demo orchestrator
├── docs/
│   ├── DECISIONS.md                       # ✅ Design decisions (student-friendly)
│   └── ARCHITECTURE.md                    # (empty — fill in as built)
├── evaluation/
│   └── make_report.py                     # ✅ Report generator
├── Makefile                               # ✅ All targets wired
├── PROGRESS.md                            # ✅ Full build log
└── README.md                              # ✅ Quickstart
```

### What needs doing (after training)

| Priority | Task | Command |
|---|---|---|
| **P0** | Train XGBoost | `source .venv/bin/activate && python models/train_xgb.py` |
| **P0** | Train LSTM-AE | `source .venv/bin/activate && python models/lstm_ae.py` |
| P1 | Eval report | `python evaluation/make_report.py` |
| P1 | Serve API | `make serve` (then test `curl localhost:8200/health`) |
| P2 | Dashboard | `make dashboard` |
| P2 | Live demo | `make demo-live` |
| P3 | Generate more slices | Fix `derive_windows_from_pcap.py` for 12h-shifted windows |
| P3 | UNSW-NB15 dataset | Add second source (generalization story for PPT) |

### Data shape (for model debugging)

After extraction, `data/features/` contains:

**Flow-window view** (for XGBoost):
- 86,550 benign rows across 5 BENIGN slices
- 3,831 Bot rows
- 11,495 DoS slowloris rows
- 33 columns (features): pkt_size_mean, iat_mean_us, rate_pkts_per_s,
  payload_entropy_mean, retrans_like_frac, flag_syn_frac/ack_frac/etc.,
  dst_port, proto, ttl_mean, etc.

**Source-bucket view** (also for XGBoost):
- 2,628 benign rows
- 150 Bot rows
- 377 DoS rows
- 19 columns: n_packets, rate_bytes_per_s, n_dst_ports, port_spread, etc.

The XGBoost trainer concatenates both views with NaN padding (the union
schema) — XGBoost handles missing values natively.

**Sequence view** (for LSTM-AE):
- 9,467 benign windows (each 50×3)
- 1,593 Bot windows
- 1,894 DoS slowloris windows

### Training parameters

**XGBoost:**
- 300 trees, max_depth=8, lr=0.15
- `eval_metric=mlogloss`, `tree_method=hist`
- `GroupShuffleSplit` by slice_id (no leakage across slices)
- Class weights: `compute_sample_weight('balanced')`
- SHAP on 2000 test-sample → top features + importance plot
- Outputs: `models/artifacts/xgb_model.joblib`, `classical_confusion.png`,
  `classical_shap.png`, `classical_metrics.json`

**LSTM-AE:**
- Architecture: LSTM(64) → Linear(16) latent → LSTM(64) → Dense(3)
- Trained on benign sequences ONLY
- MSE loss, Adam lr=1e-3, cosine annealing
- Early stop (patience 8)
- Threshold: 95th percentile of benign validation reconstruction error
- Outputs: `models/artifacts/lstm_ae.pt`, `lstm_ae_config.json`,
  `ae_metrics.json`, `ae_errors.png`

### Common pitfalls for the next model

1. **`capinfos -c` prints `45 k`** — awk `$NF` gives "k" not "45". Must
   parse the colon-delimited value from the whole line, not the last field.
   See `replay/replay_slice.sh:14` for the working awk expression.

2. **Veth MTU 9000** — CICIDS2017 has jumbo frames. If replay starts failing
   with "Failed packets", check `ip link set veth-* mtu 9000`.

3. **Diode teardown** — Before re-running setup, always
   `bash diode/teardown_diode.sh` first. Namespace names collide.

4. **Netfilter issues** — The iptables OUTPUT DROP in ns-monitor also blocks
   ICMP port unreachable messages generated by the monitor kernel. This is
   correct behavior (the diode should not leak even ICMP back).

5. **Ram constraint** — 5.8 GB. The extractor uses dpkt streaming (no full
   pcap load). If modifying it, never `pd.read_csv(file)` on large files
   without `usecols` or chunks.

6. **GeneratedLabelledFlows CSVs** — use `encoding='latin-1'` not 'utf-8';
   some fields contain invalid UTF-8 bytes.

### File structure quick reference

| Important file | Purpose |
|---|---|
| `replay/derive_windows_from_pcap.py` | Finds attack windows by scanning attacker IPs in pcaps |
| `replay/make_slices.py` | Cuts slice pcaps via editcap |
| `replay/replay_slice.sh` | Replays one slice through diode + captures monitor side |
| `extraction/extract_features.py` | Forward-only feature extractor (3 views) |
| `models/train_xgb.py` | XGBoost trainer (reads parquet files) |
| `models/lstm_ae.py` | LSTM-AE trainer (reads npz files) |
| `fusion/score.py` | Combines XGBoost + AE into one threat score |
| `serving/live_pipeline.py` | Real-time monitor-side pipeline for demo |
| `docs/DECISIONS.md` | Design reasoning + explanations (start here) |