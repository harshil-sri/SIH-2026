# SIH26145 — AI-Based Detection of Cyber Threats in Unidirectional IP Traffic
### Technical Build Plan (Base Reference Document)

**Issuing body:** NTRO
**Team:** Naman & Yuv (Cybersecurity), Karthik (AI/ML), Sagar & Rhythm (Flexible)
**Target:** Internal hackathon selection — working prototype + PPT
**Diode strategy:** Software-emulated unidirectional link (netns/iptables/UDP)
**ML strategy:** Hybrid — classical baseline + one deep learning model

---

## 1. Problem Framing

A data diode / unidirectional gateway physically (or, here, logically) allows traffic in one direction only — source → monitor, never monitor → source. This breaks the assumptions almost every existing IDS is built on:

- No handshake completion visibility (a source-side SYN scan never gets its SYN-ACK back through the diode, so classic scan-detection heuristics built on completed/half-open connection counts don't transfer)
- No RTT, no ACK-based flow features, no bidirectional byte/packet ratios (the "bwd_*" half of every CICFlowMeter-style feature set simply doesn't exist)
- Most traffic across a real diode is UDP or a custom one-way protocol, not TCP, because TCP's ACK requirement can't be satisfied

This is genuinely why "no academic paper directly addresses AI threat detection in unidirectional/data-diode environments" holds up — the standard tooling (CICFlowMeter, most public IDS pipelines) has to be adapted, not just applied. That adaptation work is the core technical contribution of this project.

### 1.1 Diode-specific threat model (this is what makes the ML non-trivial)

Because return traffic is impossible, attackers operating against a diode-protected environment are pushed toward a specific, narrower set of attack patterns — which is actually a gift for scoping the ML problem:

| Threat class | What it looks like at the diode | Why rules alone can't catch it |
|---|---|---|
| Volumetric / DoS on the monitor path | Sudden spike in packet rate / byte rate from one or few sources | Threshold rules generate false positives on legitimate bursts (e.g. historian sync) |
| Protocol anomalies / malformed frames | Malformed headers, unexpected field values, off-spec payload lengths | Requires learning "normal" protocol shape, not a fixed signature |
| Covert timing channels | Data exfiltrated by encoding it in inter-packet timing (a diode can't be defeated by sending data back, but timing *of forward-only* packets can leak information) | Statistically subtle — needs sequence modeling of inter-arrival times, not a single-packet rule |
| Payload steganography | Malicious/exfiltrated content hidden inside payloads of otherwise-legitimate one-way transfers | Needs entropy/statistical anomaly detection on payload, not signature matching |
| Malicious payload injection | A compromised source-side node injects malicious files/commands into the permitted one-way stream | Needs behavioral baselining of "what this source normally sends" |

Note the pattern: every one of these is a *statistical deviation from learned normal behavior*, not a fixed signature. That's the practical argument for why this specific problem statement requires a trained model to execute the actual detection — worth keeping in your back pocket for the teammate conversation.

---

## 2. System Architecture

```
[Traffic Source: benign + attack generators]
              │  (one-way only)
              ▼
   ┌─────────────────────────┐
   │  Emulated Data Diode     │   netns + veth + iptables/tc (policy layer)
   │  (ns-source → ns-monitor)│   + raw one-way UDP relay (transport layer)
   └─────────────────────────┘
              │
              ▼
      [Capture Layer]            tcpdump / scapy sniff on monitor side ONLY
              │
              ▼
   [Forward-only Feature         custom Python extractor (scapy/dpkt)
    Extraction Pipeline]         — no bwd_* features exist, by design
              │
              ▼
   ┌─────────────────┬─────────────────────┐
   │  Classical Model │   DL Model           │
   │  RF / XGBoost    │   LSTM-Autoencoder   │
   │  (known attack   │   (anomaly / novel   │
   │   types, labeled)│    threats, unsup.)  │
   └─────────────────┴─────────────────────┘
              │
              ▼
      [Alert Fusion Layer]        combine classifier confidence +
                                   reconstruction-error threshold
              │
              ▼
   [FastAPI inference service] → [Dashboard: live traffic + alerts]
```

---

## 3. Diode Emulation Environment

Two layers, so you can honestly say in the PPT "we enforce unidirectionality at both the policy layer and the transport layer":

**Policy layer (fast to set up):**
```bash
ip netns add ns-source
ip netns add ns-monitor
ip link add veth-src type veth peer name veth-mon
ip link set veth-src netns ns-source
ip link set veth-mon netns ns-monitor
# assign IPs, bring interfaces up...

# In ns-monitor: drop every outbound packet — monitor can receive, never send
ip netns exec ns-monitor iptables -A OUTPUT -j DROP
```

**Transport layer (stronger guarantee, do this too):**
A small Python relay where the source-side process only ever calls `sendto()` on a raw/UDP socket and the monitor-side process only ever calls `recvfrom()` — there is no code path for a return message, which is closer in spirit to how a hardware diode works than a firewall rule is.

Be upfront in the PPT that this is a *software emulation* of a hardware data diode — judges will respect the honesty more than a vague implication of real hardware, and it doesn't weaken the ML contribution at all.

**Optional upgrade if time allows:** [Mininet](http://mininet.org/) instead of raw netns, if you want a cleaner virtual topology with more than 2 nodes (e.g. multiple source-side sensors → one diode → one monitor) — nice for the "wow factor" live visualization since Mininet topologies render well.

---

## 4. Datasets

No public dataset is literally "captured through a data diode" — that gap is exactly your novelty angle. Strategy: **use established labeled attack datasets as raw material, replay them through your emulated diode, and let the diode's constraints (drop return traffic, keep only forward-direction packets) produce your actual training data.**

| Dataset | Why it's useful here |
|---|---|
| **CICIDS2017 / CICIDS2018** (Canadian Institute for Cybersecurity) | Large labeled attack traffic — DoS, port scan, brute force, botnet, web attack, infiltration. Raw pcaps can be replayed with `tcpreplay` through the emulated diode. |
| **UNSW-NB15** | Modern attack taxonomy, good second source to reduce single-dataset bias, useful for the classical model's generalization story. |
| **CIDDS-001** | Already published in **unidirectional NetFlow format** — good reference/sanity-check dataset for what "one-way flow features" should look like, and a legitimate citation for your literature section. |
| **CIC-DDoS2019** | Strong DoS/DDoS coverage — directly relevant to the "volumetric attack on the monitor path" threat class. |
| **SWaT / WADI** (iTrust Centre, SUTD Singapore) | Real ICS/OT testbed attack data (water treatment / water distribution). Data diodes are overwhelmingly deployed in ICS/OT/critical-infrastructure contexts, so this is your strongest domain-match dataset for the NTRO framing, even though it's not IP-traffic-native — worth at least referencing in the report even if you don't train directly on it. |
| **Self-generated (your real contribution)** | Custom Scapy scripts crafting diode-specific attacks: UDP floods, malformed/off-spec frames, deliberately timed covert-channel packet sequences, payload steganography samples. This is what actually makes the "AI-based" claim defensible rather than a rebadged CICIDS model. |

---

## 5. Feature Engineering (forward-only, by construction)

Because there is no return path, every feature must be computable from a one-way packet stream alone. Two feature sets, matching the two models:

**A. Flow/window-aggregated tabular features** (for the classical model)
- Packet size: mean, std, min, max per flow/window
- Inter-arrival time (IAT): mean, std, min, max — this is your primary signal for covert timing channels
- Packet/byte rate over sliding time window (e.g. 1s, 5s windows)
- Protocol and port distribution
- Payload entropy (Shannon entropy — flags encrypted/encoded exfil or steganographic payloads)
- TTL distribution
- Retransmission-like behavior (repeated identical-looking packets — since a diode blocks the ACK, real retransmits look different from normal traffic and are themselves a mild anomaly signal)

**B. Raw packet sequences** (for the DL model)
- Ordered sequence of (packet size, IAT, protocol one-hot) tuples per source, in sliding windows — this preserves the temporal texture that aggregation destroys, which is exactly what you need to catch a slow-drip timing-channel exfiltration that a flow-level average would smooth away.

Extraction tool: write a small custom extractor with `scapy`/`dpkt` rather than relying on off-the-shelf CICFlowMeter — CICFlowMeter assumes bidirectional flows and computes half its features from backward traffic that won't exist here. Building this extractor yourself is a legitimate, demoable technical artifact in its own right (worth a slide).

---

## 6. Tech Stack & Libraries

| Layer | Tool/Library |
|---|---|
| OS / emulation | Ubuntu (WSL2 fine), `ip netns`, `veth`, `iptables`/`nftables`, `tc` |
| Packet crafting/replay | `scapy`, `tcpreplay`, `tcpdump`, `tshark`/`pyshark` |
| Feature extraction | `scapy`, `dpkt`, `pandas`, `numpy` |
| Classical ML | `scikit-learn` (Random Forest, Isolation Forest), `xgboost` or `lightgbm` |
| Class imbalance | `imbalanced-learn` (SMOTE) — attack traffic will be rare relative to benign |
| Deep learning | `PyTorch` — LSTM-Autoencoder for sequence anomaly detection |
| Explainability | `shap` — feature importance on the RF/XGBoost model (judges respond well to this; also strengthens the "this isn't a black box" answer) |
| Serving | `FastAPI` for the inference API |
| Dashboard / demo | `Streamlit` (fastest to build for a hackathon timeline) or a lightweight `FastAPI` + WebSocket + Chart.js frontend if you want more visual control for the "live diode visualization" wow factor |
| Model export | `joblib` (sklearn), `torch.save` + optionally ONNX export if you want to show low inference latency numbers on a slide |

---

## 7. ML Models (hybrid, as decided)

**Classical baseline — Random Forest / XGBoost**
- Trained on the tabular flow-level features from your replayed, labeled datasets (CICIDS2017/2018, UNSW-NB15, CIC-DDoS2019 → diode-filtered)
- Multi-class or binary classification (benign vs. attack-type)
- Fast, interpretable via SHAP, easy to demo live inference (<1ms per flow) — this is your "known attack types" detector

**Deep learning — LSTM-Autoencoder**
- Trained **only on benign packet sequences** (unsupervised) to reconstruct normal one-way traffic patterns
- At inference, reconstruction error above a tuned threshold = anomaly flag
- This is your "unknown/novel/zero-day threat" detector — the framing directly matches NTRO's likely interest (signature-based tools miss exactly this category), and it doesn't need labeled attack data to work, which is realistic for a diode-protected environment where you may never see every attack type in advance
- 8GB VRAM (RTX 4060) is comfortably enough for this — it's a small sequence model on packet-level features, not image-scale training, so expect minutes-to-an-hour training runs, not multi-hour

**Alert fusion**
- Final alert = combine classifier confidence (known-type detection) with autoencoder reconstruction error (novel-type detection) into a single threat score, with separate thresholds tuned via the precision/recall tradeoff below

---

## 8. Evaluation Plan

- Precision / Recall / F1 per attack class — prioritize recall on rare classes, but report precision too (a live NTRO context means false-positive/alert-fatigue is a real judged concern, not just an academic footnote)
- ROC-AUC and PR-AUC (PR-AUC matters more here given class imbalance)
- Confusion matrix
- False Positive Rate at your chosen operating threshold
- **Inference latency (ms per flow/window)** — put this on a slide explicitly; "low-latency detection in a constrained one-way environment" is a direct callback to the problem statement's own framing

---

## 9. Demo / Dashboard

Given the "wow factor: live data diode visualization with threat alerts" already identified as a strength, the fastest path to a convincing live demo:

1. `tcpreplay` a mix of benign + attack pcaps through the emulated diode in real time
2. FastAPI service consumes the monitor-side capture, runs both models per window, emits alerts over a WebSocket
3. Dashboard (Streamlit or Chart.js) shows: live packet flow visualization, a running threat score, and a flagged-alert feed with the model's reasoning (SHAP top features for classical hits, reconstruction error for anomaly hits)

---

## 10. Team & Roles

- **Cybersecurity (Naman & Yuv):** diode emulation setup and validation (prove it's genuinely one-way with tcpdump evidence), threat taxonomy definition, Scapy attack-script authoring, ground-truth labeling, validating that flagged detections correspond to real attack behavior, security-framing slides in the PPT
- **AI/ML (Karthik, with Harshil driving overall architecture/planning):** feature extraction pipeline, both models, evaluation, SHAP explainability, FastAPI inference service, dashboard integration, ML-framing slides in the PPT
- **Flexible (Sagar & Rhythm):** float to whichever side is behind pace — likely attack-script volume / labeling on the cybersecurity side early on, and eval/dashboard polish on the ML side later

---

## 11. Build Timeline (internal-hackathon pace)

| Day | Milestone |
|---|---|
| 1–2 | Diode emulation working, verified one-way with tcpdump (zero reverse packets) |
| 2–3 | Traffic generation: replay public datasets + custom Scapy attack scripts through the diode, capture raw pcaps |
| 3–4 | Feature extraction pipeline → labeled tabular dataset + packet-sequence dataset |
| 4–5 | Train + evaluate Random Forest/XGBoost baseline |
| 5–6 | Train + tune LSTM-Autoencoder, set reconstruction-error threshold |
| 6–7 | FastAPI service + dashboard wired to live replay, end-to-end demo working |
| Final day | PPT polish, demo video recording, rehearsal |

---

## 12. Known Risks & Mitigations

- **No real diode-captured ground truth exists** → mitigated by the replay-through-emulation approach; be transparent about this being simulated, not claim otherwise
- **Domain gap** between enterprise traffic (CICIDS-style) and real OT/ICS diode traffic (Modbus/DNP3 etc.) → reference SWaT/WADI in the report even if not trained on directly, to show awareness of the gap
- **Class imbalance** → SMOTE + PR-AUC as primary metric, not just accuracy
- **Autoencoder threshold tuning** can be finicky under time pressure → start threshold search early (Day 5), don't leave it to the last day

---

## 13. Stretch Goals (if time permits)

- Mininet-based multi-source topology for a richer live visualization
- ONNX export + latency benchmarking slide
- Federated/incremental retraining story (if judges ask "how does this adapt to new threats post-deployment")
