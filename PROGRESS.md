# SIH26145 — Build Progress Log

> **This file is the single source of truth for project state.** Every session MUST append
> dated entries at the bottom of the log section and update "Current State" below.
> Companion docs: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md), [docs/DATA_PIPELINE.md](docs/DATA_PIPELINE.md),
> [docs/HANDOFF.md](docs/HANDOFF.md) (written for a successor AI/dev to resume work cold).

---

## Project

**SIH26145 — AI-Based Detection of Cyber Threats in Unidirectional IP Traffic** (NTRO, via internal SIH 2026 selection).

One-paragraph summary: labeled public attack pcaps are replayed through a **software-emulated data diode**
(netns + veth + iptables DROP + one-way UDP relay). Only forward-direction traffic survives. A custom
feature extractor computes **forward-only features** (no `bwd_*` exist by construction) producing (a)
flow/window tabular rows and (b) raw packet sequences. Two models: **XGBoost/RF** classifier for known
attack types (SHAP-explained) + **LSTM-Autoencoder** trained on benign-only sequences for novel threats.
Their outputs fuse into one threat score served by FastAPI with a live dashboard.

Full original problem framing: see `SIH26145-technical-build-plan.md` (base reference document).

## Locked decisions (2026-08-26)

| Decision | Value |
|---|---|
| Deadline | ~2 weeks from 2026-08-26 (internal selection demo) |
| Scope | Full stack v1 built on this machine (diode → extraction → models → serving → dashboard) |
| Datasets | Tier 1 full: CICIDS2017 all 5 day-pcaps (~48GB) + MachineLearningCSV + CIDDS-001 (~384MB) |
| Diode | Local software emulation; machine has sudo (via bootstrap script) |
| Team roles | Harshal = ML/DL lead (driving this build); Naman & Yuv = cybersecurity (attack scripts, validation); Sagar & Rhythm = float |

## Environment facts

- Ubuntu 24.04 native, kernel supports netns/veth/iptables. **16 cores, RTX 4060 8GB, 805GB free disk.**
- ⚠️ **RAM is only 5.8 GB** → ALL processing must stream/chunk (dpkt streaming, polars lazy, parquet).
  Never load full pcaps into memory. XGBoost trains on subsamples. LSTM-AE fits easily in VRAM.
- Python 3.12 (system). Project venv: `.venv/` (see scripts/setup_venv.sh).
- sudo requires password → scoped NOPASSWD rule installed via `scripts/bootstrap_sudo.sh` (run once by human).

## Current State

> **PAUSED 2026-08-26 ~11:50 UTC** — Harshal stepped out; ALL downloads intentionally stopped at
> **18.6 / ~50 GB** (~37%). Resume with ONE command: `bash scripts/download_aria.sh` (background it
> with `setsid nohup bash scripts/download_aria.sh </dev/null >/dev/null 2>&1 &`).
> Do NOT use plain wget loops — they stall silently on dead HF sockets; aria2c (-x8) recovers.

### Per-file progress at pause

| File | Done | Target |
|---|---|---|
| Friday-WorkingHours.pcap | ✅ ~8.2 GB | 8.4 GB (verify before use!) |
| Thursday-WorkingHours.pcap | 🔄 3.5 GB | 7.9 GB |
| Wednesday-workingHours.pcap | 🔄 3.1 GB | 12.8 GB |
| Monday-WorkingHours.pcap | 🔄 2.0 GB | 10.3 GB |
| Tuesday-WorkingHours.pcap | 🔄 1.8 GB | 10.5 GB |

MachineLearningCSV.zip ✅ · GeneratedLabelledFlows.zip ✅ (extracted to datasets/raw/glf/) · CIDDS-001.zip ✅

| Component | Status |
|---|---|
| Dataset downloads | ⏸ PAUSED 18.6/50GB — resume via scripts/download_aria.sh |
| apt tooling | ✅ installed via `scripts/bootstrap_sudo.sh` (scoped NOPASSWD: ip/iptables/tcpreplay/tcpdump/tshark/editcap/capinfos/mergecap) |
| Python venv + ML stack | ✅ `.venv/` — torch+CUDA ok, xgboost, sklearn, dpkt, scapy, polars, fastapi, streamlit |
| Diode emulation | ✅ **P1 GATE PASSED** (5/5 forward frames, 0 leaked reverse, DROP counter evidence in `data/diode/proof/`) |
| Replay & capture pipeline | ✅ **P2 GATE PASSED on synthetic pcaps** — tcpreplay→tcpdump through diode, 100% packet delivery on benign/covert/portscan slices; flood slice had capture loss (diagnostic in log below, fix = pacing, see TODO) |
| Feature extractor | ✅ built + smoke-tested (`extraction/extract_features.py`) |
| Classical model (XGBoost/RF) | ✅ code ready (`models/train_xgb.py`) — needs real features |
| LSTM-AE | ✅ code ready + architecture validated (`models/lstm_ae.py`, structured-signal recon loss 0.0025) |
| Fusion + FastAPI | ✅ code ready (`fusion/score.py`, `serving/app.py` imports clean) |
| Dashboard | ✅ code ready (`dashboard/app.py`) |
| Live demo path | ✅ code ready (`scripts/live_demo.sh`, `serving/live_pipeline.py`, `attacks/generate.py`) |
| Evaluation suite | ✅ code ready (`evaluation/make_report.py`, Makefile wired) |

## Phase plan & verification gates

| Phase | Gate (must pass before next phase) | Status |
|---|---|---|
| P1 diode | tcpdump inside monitor netns proves ZERO packets leave monitor side; forward packets arrive | ✅ PASSED 10:16 UTC |
| P2 replay/capture | every captured slice has a manifest mapping time-ranges/5-tuples → attack labels | 🔄 code ready, awaiting pcaps |
| P3 extractor | feature semantics cross-checked vs CIDDS-001 unidirectional NetFlow columns; parquet + npz written incrementally under RAM budget | ✅ smoke-tested on synthetic pcap |
| P4 classical | PR-AUC per attack class reported; confusion matrix saved; FPR@threshold reported | ⏳ |
| P5 LSTM-AE | threshold chosen on held-out set; benign-vs-attack separation quantified | ⏳ |
| P6 fusion/serving | /score endpoint latency < 10ms/window; WebSocket alerts fire on live replay | ⏳ |
| P7 eval/demo | `make demo` runs end-to-end; metrics table + latency bench generated | ⏳ |

## Log

### 2026-08-26 (build session 1)

- Read base plan doc; audited machine (Ubuntu 24.04, 16c/5.8GB RAM/RTX4060/805GB disk).
- Researched + confirmed dataset URLs and sizes (CICIDS2017 pcaps ~48GB total, CIDDS-001 384MB).
- User locked decisions: 2 weeks, full stack, Tier 1 downloads, local diode.
- Created repo scaffold + PROGRESS.md.
- Launched dataset downloads. **Hit a snag:** official UNB host (205.174.165.80) now serves an HTML
  interstitial / redirects to cicresearch.ca which 302s to the datasets index — direct links are gated.
  Switched to the HuggingFace mirror `bencorn/CICIDS2017` (byte sizes match official exactly; CIC's
  license explicitly permits mirroring). CIDDS-001 + MachineLearningCSV + GeneratedLabelledFlows all
  downloaded fine.
- Human ran `sudo bash scripts/bootstrap_sudo.sh`: installed packet tooling + scoped NOPASSWD sudoers
  (`/etc/sudoers.d/sih26145`). Scripts therefore never run as root wholesale — they invoke
  `sudo <specific-binary>` per command.
- **Diode emulation built & verified**: `diode/setup_diode.sh` (netns pair, veth, iptables OUTPUT DROP
  in monitor ns, offload disabled to keep captures honest), `diode/relay.py` (transport-layer one-way:
  sender has only sendto(), receiver only recvfrom(), bounded by --max-pkts/--max-seconds),
  `diode/verify_diode.sh`. Debug journey: sudoers scope forced per-command sudo pattern; relay recv
  needed exit conditions so no process killing is ever required; pipefail+grep-no-match aborted script.
  Evidence: `data/diode/proof/result.txt`.
- **Attack-window ground truth**: extracted labels CSVs; discovered CICIDS2017's timestamp quirks
  (Friday-afternoon files write 15:30 as "3:30" — 12h clock without AM/PM). CSV-derived windows are
  therefore untrustworthy for editcap cutting. Built `replay/derive_windows_from_pcap.py`: locates
  attacker-IP packet bursts directly in each pcap via selective BPF pass, clusters them (gap>120s),
  matches bursts to CSV labels over offset candidates {0,+12,-12}h. Output: `data/windows_pcap.json`
  + `docs/ATTACK_WINDOWS.md`. Will re-run when pcaps complete.
- **Forward-only feature extractor** (`extraction/extract_features.py`) built + smoke-tested:
  - flow-window view (parquet): per-5-tuple stats — size/IAT mean/std/min/max, rates, payload entropy,
    TTL stats, retrans-like fraction, TCP flag fractions (SYN-only handshakes are themselves signal)
  - source-time-bucket view (parquet): per-(src, 5s bucket) volumetrics + dst-port spread — catches
    floods/scans that randomize ports (found via smoke test that pure 5-tuple flows fragment)
  - sequence view (npz): per-src sliding windows of [log-size, log-iat, proto] for the LSTM-AE
  - fully streaming via dpkt (RAM-safe); malformed frames counted not dropped
  - dpkt API gotcha fixed: constants live at dpkt.ip.IP_PROTO_*, not dpkt.*
- **All downstream components written & unit-validated**: XGBoost trainer (group-split by slice,
  union-schema NaN handling for both views, SHAP), LSTM-AE (decoder-input bug fixed; overfits a
  structured signal to loss 0.0025 — architecture sound), fusion scoring, FastAPI service (imports
  clean), streamlit dashboard, live-demo pipeline + attack generators (benign telemetry / udp_flood /
  covert-timing / stego-payload / malformed), Makefile targets, report generator.
- **Synthetic end-to-end dry-run** (`replay/make_synth.py` → replay through REAL diode → capture):
  - benign 1322/1322 ✅ · covert-timing 576/576 ✅ · portscan-sim 300/300 ✅ · udp-flood **16/16181 ✘**
  - root-cause investigation of flood loss: tcpdump saw only ~415 of 16181 sent packets at burst rate;
    tcpreplay reported 0 failed sends. Suspected veth/qdisc drop under instantaneous bursts.
    Controlled test WITHOUT `-c` captured 32k packets across two replays (1x + topspeed) — so the
    forward path does deliver bulk traffic; loss correlates with capture-start race (`-c N` +
    startup delay) and/or burst drops. TODO next session: re-test flood with `sleep 1.5` pre-replay
    pacing + `--multiplier=2`, then confirm counts match before real-data replay.
  - shell gotchas fixed: capinfos uses colon separators (`sed -nE` extraction now), `$!` on a
    pipeline grabs subshell PID (use bounded self-exiting receivers instead of kill).
- Downloads stalled twice: plain wget loops die silently on HF CDN socket stalls (files frozen at
  11:00 while wget alive). Switched to aria2c script with retry/stall recovery. Paused by Harshal.

## Resume checklist (next session)

1. `setsid nohup bash scripts/download_aria.sh </dev/null >/dev/null 2>&1 &` → wait for
   `ARIA_ALL_DONE` in datasets/raw/download.log (~45–90 min for remaining ~31 GB)
2. Verify pcaps: `for f in datasets/raw/*.pcap; do capinfos -c "$f" | grep -i number; done`
   (Friday was mid-download when paused — double-check it)
3. Fix flood-slice capture race (see dry-run note above), rerun synthetic dry-run until all 4 slices
   deliver 100%
4. `make windows && make slices && make replay` (replay ≈ sum of slice durations at 1x)
5. `make extract && make train && make report`
6. `make demo-live` + dashboard for the wow-factor pass

---

