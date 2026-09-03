# SIH26145 — Design Decisions & Reasoning

> Written for a bachelor's student (you!) who's the ML/DL lead. Each section
> explains what decision was made, **why**, and what tradeoffs it involves.
> No jargon assumed — if something sounds complex, the explanation is below it.

---

## 1. Dataset: CICIDS2017 via HuggingFace mirror

**Decision:** Use CICIDS2017 (5 day-pcaps, ~50 GB total) downloaded from
`bencorn/CICIDS2017` on HuggingFace instead of the official UNB website.

**Why:** The UNB site now requires you to fill out a web form and set cookies.
Our download script (wget/curl) can't do that, so it gets back an HTML page
instead of the actual pcap files. HuggingFace is an authorized mirror — the
bytes are identical, and UNB's license explicitly says "you may redistribute,
republish and mirror our datasets in any form".

**What about the other datasets?** We also downloaded:
- **CIDDS-001** (384 MB) — already in **unidirectional NetFlow format**!
  Perfect as a sanity check that our forward-only features look correct.
- **MachineLearningCSV.zip** + **GeneratedLabelledFlows.zip** — these have the
  ground-truth labels (what traffic was benign vs attack, and what kind of
  attack) used to label our replayed traffic.

**Download gotcha:** HuggingFace's CDN sometimes stalls for minutes at a time.
Plain `wget` hangs forever when this happens. Solution: `aria2c` with
`-x8 -s8` (8 parallel connections per file, auto-retry on stalls).

---

## 2. Data Diode Emulation: netns + iptables + Python relay

**Decision:** Emulate the data diode in three layers:
1. **Policy layer:** Two Linux network namespaces (`ns-source`, `ns-monitor`)
   connected by a virtual Ethernet pair (veth). An `iptables OUTPUT DROP` rule
   in the monitor namespace kills any packet that tries to leave the monitor.
2. **Transport layer:** A Python relay program where the sender runs in
   `ns-source` and **only ever calls `sendto()`** (no receive code path), while
   the receiver runs in `ns-monitor` and **only ever calls `recvfrom()`**.
3. **Physical proof:** tcpdump captures on both sides prove zero packets ever
   leave the monitor namespace (evidence saved in `data/diode/proof/`).

**Why two layers?** A firewall rule alone could be bypassed or misconfigured.
Having both a policy rule AND a structurally one-way program means we can say
honestly in the PPT: "we enforce unidirectionality at both the policy and
transport layers." The relay program is closer in spirit to how a real hardware
diode works.

**Tradeoff:** This is a *software emulation* of a hardware diode, not real
hardware. We're upfront about this — it doesn't weaken the ML contribution
(the difficulty is still the same: learning from forward-only traffic).

---

## 3. Attack Window Derivation: pcap-based, not CSV-based

**Decision:** Find attack windows by scanning the pcap files directly with
tcpdump (searching for packets from known attacker IPs), not from the CSV
timestamps.

**Why:** CICIDS2017 has a notorious bug: the Friday afternoon CSV file writes
times in 12-hour format without AM/PM. So `3:30 PM` is written as `3:30`
instead of `15:30`. If you use these CSV timestamps directly, your attack
windows are shifted by 12 hours and you cut empty slices (we learned this the
hard way — first attempt produced zero-packet slices).

The script `replay/derive_windows_from_pcap.py` fixes this by:
1. Reading the attacker IPs from the CSV labels (e.g., "the BruteForce
   attack came from IP 172.16.0.1")
2. Scanning the actual pcap for every packet from that attacker
3. Finding where those packets cluster into bursts (separated by >2 min gaps)
4. Matching each burst cluster to the right label

**Result:** Of 15 intended attack windows, only ~6 had pcap-verified content.
The rest (SSH-Patator, FTP-Patator, Web Attacks, most Wednesday DoS) shared
IPs with other attacks and their bursts got merged together. This is acceptable
for v1 — the model still learns real attack vs benign patterns.

---

## 4. Slice Strategy: 4-min attack clips with 1-min benign margins

**Decision:** Each attack window is sliced into a single pcap file of up to
4 minutes, bookended by 1 minute of benign context on each side.

**Why:**
- Full replay at 1x speed: 4 min attacks × ~10 slices = 40 min. That's
  reasonable for a hackathon demo.
- Benign context gives the model examples of "normal" traffic immediately
  before/after attacks, which helps it distinguish attack patterns from
  baseline noise.
- The 4-min cap prevents a single long attack (like a 6-hour botnet scan)
  from monopolizing training time.

**Tradeoffs:** Longer slices would give more data per attack, but fewer
distinct attack examples. For v1, diversity > quantity per class.

---

## 5. Feature Extraction: Two Views + Sequence View

**Decision:** Extract three separate feature views from the forward-only
captures:

### View A: Flow-Window View (per-5-tuple time windows)
Each packet belongs to a "flow" defined by its 5-tuple:
`(src_ip, src_port, dst_ip, dst_port, protocol)`. When a flow is idle for
>5 seconds or exceeds 200 packets, it's closed and we compute statistics:
- Packet size: mean / std / min / max
- Inter-arrival times (IAT): mean / std / min / max
- Rates: bytes per second, packets per second
- Payload entropy: Shannon entropy of the content (measures randomness —
  encrypted/random payloads have high entropy)
- TTL stats: mean/min/max
- Retransmission-like fraction: how many packets are near-duplicates
  (suspicious in a one-way environment since there's no ACK)
- TCP flag fractions: SYN / ACK / PSH / FIN / RST ratios (through a
  diode, TCP never completes handshakes — SYN-only connections are
  themselves a signal)

### View B: Source-Bucket View (per-source-IP time windows)
Groups ALL packets from each source IP into fixed 5-second buckets.
This catches attacks that randomize ports to evade per-flow detection.
Features:
- Packet count and byte total per bucket
- Rates (pps, bps)
- Number of distinct destination ports and IPs (port-scans show up here)
- IAT mean/std
- Payload entropy

**Why two views?** A UDP flood from a bot that randomizes its source ports
creates 10,000 separate 1-packet flow-windows (View A). Each one looks
innocent. But the same flood creates ONE source-bucket window (View B)
showing 10,000 packets at high rate with many dst ports. Together they
cover each other's blind spots.

### View C: Sequence View (for the LSTM-AE)
Sliding windows of 50 consecutive packets from each source IP. Each
window is `[log1p(packet_size), log1p(IAT), protocol_code]` (3 features
per packet). The logs compress the range so one giant packet doesn't
dominate.

**Why sequences?** Aggregation destroys temporal texture. A slow-drip
covert timing channel that embeds one bit every 50ms into inter-packet
delays looks statistically normal in a 5-second bucket. But the sequence
of 50 packets shows the bit pattern clearly.

---

## 6. Model Architecture: XGBoost + LSTM-Autoencoder

**Decision:** Two models instead of one.

### XGBoost Classifier (for known attacks)
- Takes the concatenated View A + View B features (XGBoost handles NaN
  values natively, so rows from View A just leave View B columns empty
  and vice versa)
- Multi-class: predicts which attack class (BENIGN, Bot, DoS slowloris)
- SHAP explainability: shows which features drove each prediction
  (important for the judges — "this isn't a black box")
- Training: grouped split by slice (no data leakage between train/test),
  class-balanced via sample weighting

**Why XGBoost over other classifiers?** Fast to train, handles mixed
feature types, has built-in sparsity (NaN handling), and SHAP works out
of the box. For a hackathon timeline it's the right choice.

### LSTM-Autoencoder (for novel/unknown threats)
- Trained on **BENIGN sequences only** (Monday traffic)
- Learns to reconstruct "normal" one-way traffic patterns
- At inference, high reconstruction error = anomaly (potential attack)
- Threshold set at 95th percentile of benign validation errors

**Why unsupervised?** In a real deployment, you can't know what novel
attacks an adversary will invent next. An autoencoder that flags
"anything that doesn't look like normal traffic" is the right tool.

### Alert Fusion
```
final_score = 0.6 × [XGBoost attack probability] +
              0.4 × [sigmoid((AE_error - threshold) / scale)]
```

---

## 7. What's Ready vs What Needs You

| Step | Status | How to launch |
|---|---|---|
| Raw datasets (50 GB) | ✅ Done | — |
| Diode emulation | ✅ Done | `bash diode/verify_diode.sh` |
| Replay slices | ✅ Done | `replay/slices/` has 6 files |
| Captures (through diode) | ✅ Done | `data/captures/` has 6 captures |
| Feature extraction | ✅ Done | `data/features/` has parquet + npz |
| **XGBoost training** | **🚀 READY** | **`source .venv/bin/activate && python models/train_xgb.py`** |
| **LSTM-AE training** | **🚀 READY** | **`source .venv/bin/activate && python models/lstm_ae.py`** |
| Evaluation report | ⏳ After training | `python evaluation/make_report.py` |
| FastAPI serving | ⏳ After training | `make serve` |
| Dashboard | ⏳ After training | `make dashboard` |
| Live demo | ⏳ After training | `make demo-live` |

---

## Known Issues & Gotchas

1. **Only 6 of 15 planned slices have content** — the CSV timestamps for
   Tuesday (SSH/FTP Patator), Thursday (Web Attacks), and most Wednesday
   (DoS Hulk/GoldenEye/Heartbleed/Slowhttptest) were shifted by 12 hours
   relative to the actual pcap data. A future version should fix
   `derive_windows_from_pcap.py` to handle these — the attack data IS in
   the pcaps, just at different times than the CSV claims.

2. **Veth MTU** — CICIDS2017 contains jumbo frames (packets > 1500 bytes).
   The default veth MTU is 1500, causing tcpreplay to fail on ~5000 packets
   per slice. Fixed by setting veth MTU to 9000 in `setup_diode.sh`. The
   capture-side MTU must match.

3. **RAM: 5.8 GB** — This machine has limited RAM. The feature extractor is
   designed to stream through pcaps without loading them fully. Training
   XGBoost on ~80k rows of tabular data is fine. LSTM-AE training on ~10k
   sequences is tiny — it'll finish in seconds on the RTX 4060.

4. **capinfos output format** — `capinfos -c` prints `Number of packets: 45 k`
   (with "k" suffix for thousands). Any shell script parsing this needs to
   strip the suffix and multiply by 1000. Standard awk won't handle "45 k"
   as a number — you need explicit suffix handling.

5. **aria2c vs wget** — HuggingFace CDN sockets sometimes stall. `wget -c`
   waits forever without recovery. `aria2c -x8` uses 8 parallel connections
   and auto-retries on stalls. Don't use wget for large HF downloads.

6. **TCP SYN-only signals** — Through a real data diode, TCP handshakes never
   complete. Every TCP packet is just a bare SYN (no SYN-ACK ever comes back).
   Our extractor records TCP flag fractions (SYN_frac close to 1.0 is itself
   a mild anomaly signal). This is realistic.

---

## Glossary (for the PPT)

| Term | What it means |
|---|---|
| **Data diode** | A network link where data flows one direction only. Source sends, monitor receives, never replies. Used in military/ICS/SCADA environments. |
| **Forward-only features** | Network statistics computed from a one-way packet stream. No information from return traffic (ACKs, RTT, etc.) — because return traffic doesn't exist. |
| **5-tuple** | (Source IP, Source Port, Dest IP, Dest Port, Protocol) — the standard way to identify a network connection. |
| **IAT** | Inter-Arrival Time — the time gap between two consecutive packets. |
| **Shannon entropy** | A measure of randomness. ASCII text has entropy ~3-4 bits/byte; encrypted data has ~8 bits/byte. High-entropy payloads in unexpected flows are suspicious. |
| **LSTM-Autoencoder** | A neural network that tries to reconstruct its input through a narrow "bottleneck". If it can't reconstruct something well (high error), that thing is unusual — possibly an attack. |
| **SHAP** | A method to explain which features most influenced a model's decision. Judges love this. |