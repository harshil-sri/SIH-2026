#!/usr/bin/env python3
"""SIH26145 — Forward-only feature extractor (the project's core technical artifact).

Computes features exclusively from a ONE-WAY packet stream — there is no
backward direction through a data diode, so nothing here uses bwd_* style
information. Where CICFlowMeter assumes bidirectional biflows, this extractor
assumes each packet observed is all the evidence that will ever exist.

Two output views per input pcap:

  A. TABULAR  (for XGBoost/RF)   -> <out>/flows_<name>.parquet
     One row per *flow-window*: same 5-tuple, broken on idle > --flow-timeout
     seconds or > --max-flow-pkts packets. All statistics are forward-only.

  B. SEQUENCES (for LSTM-AE)     -> <out>/seqs_<name>.npz
     Per source IP, sliding windows over the packet stream of
     [log-size, log-iat, proto-code] triples — temporal texture that
     aggregation would destroy (this is what catches slow-drip timing channels).

Streaming design (machine has 5.8 GB RAM):
  - dpkt reads the pcap sequentially; nothing is buffered wholesale.
  - Active flows held in a dict; a periodic sweep evicts idle ones.
  - Rows flushed incrementally; memory scales with concurrent flows, not size.

Usage:
  python extraction/extract_features.py <capture.pcap> \
      --label "DoS Hulk" --slice-id wednesday__dos-hulk__0 \
      --out-dir data/features [--flow-timeout 5] [--max-flow-pkts 200]
"""
import argparse
import hashlib
import json
import math
import sys
from collections import deque
from pathlib import Path

import dpkt

# ---------------------------------------------------------------- utilities

def shannon_entropy(b: bytes) -> float:
    """Shannon entropy (bits/byte) of a payload snippet; 0.0 when empty."""
    if not b:
        return 0.0
    counts = [0] * 256
    for byte in b:
        counts[byte] += 1
    n = len(b)
    return -sum((c / n) * math.log2(c / n) for c in counts if c)


def safe_div(a: float, b: float) -> float:
    return a / b if b else 0.0


def stats(vals):
    """mean/std/min/max with deterministic empty-case values."""
    if not vals:
        return 0.0, 0.0, 0.0, 0.0
    n = len(vals)
    mean = sum(vals) / n
    var = sum((v - mean) ** 2 for v in vals) / n
    return mean, math.sqrt(var), min(vals), max(vals)

# ---------------------------------------------------------------- extractor

class FlowWindow:
    """Running accumulator for one (5-tuple, burst) — forward direction only."""
    __slots__ = ("src", "sport", "dst", "dport", "proto", "t_first", "t_last",
                 "sizes", "iats", "entropies", "ttls", "payload_hashes",
                 "n", "bytes_sum", "flags")

    def __init__(self, key, t, size, ent, ttl, phash):
        self.src, self.sport, self.dst, self.dport, self.proto = key
        self.t_first = self.t_last = t
        self.sizes = deque(maxlen=4096)
        self.iats = deque(maxlen=4096)
        self.entropies = deque(maxlen=1024)
        self.ttls = deque(maxlen=1024)
        self.payload_hashes = deque(maxlen=64)   # bounded: retrans-fraction estimate
        self.n = 0
        self.bytes_sum = 0
        self.flags = {"syn": 0, "ack": 0, "psh": 0, "fin": 0, "rst": 0, "urg": 0}
        self.add(t, size, ent, ttl, phash)

    def add(self, t, size, ent, ttl, phash):
        if self.n:
            self.iats.append(t - self.t_last)
        self.sizes.append(size)
        if len(self.entropies) < self.entropies.maxlen:
            self.entropies.append(ent)
            self.ttls.append(ttl)
            self.payload_hashes.append(phash)
        self.t_last = t
        self.n += 1
        self.bytes_sum += size


class SourceWindow:
    """Per (source IP, time bucket) accumulator — port-randomization-proof
    volumetric/scan features. A UDP flood that spawns 10k ephemeral 5-tuples
    still shows up here as ONE row with huge n_packets + huge dst-port spread."""
    __slots__ = ("n", "bytes_sum", "dst_ports", "dst_ips", "iats", "entropies",
                 "ttls", "t_first", "t_last", "protos")

    def __init__(self):
        self.n = 0
        self.bytes_sum = 0
        self.dst_ports = set()
        self.dst_ips = set()
        self.iats = deque(maxlen=2048)
        self.entropies = deque(maxlen=512)
        self.ttls = deque(maxlen=512)
        self.protos = set()
        self.t_first = None
        self.t_last = None

    def add(self, t, size, dport, dip, proto, ent, ttl):
        if self.t_first is None:
            self.t_first = t
        elif len(self.iats) < self.iats.maxlen:
            self.iats.append(t - self.t_last)
        self.t_last = t
        self.n += 1
        self.bytes_sum += size
        if len(self.dst_ports) < 4096:
            self.dst_ports.add(dport)
        if len(self.dst_ips) < 512:
            self.dst_ips.add(dip)
        self.protos.add(proto)
        if len(self.entropies) < self.entropies.maxlen:
            self.entropies.append(ent)
            self.ttls.append(ttl)


TCP_FLAG_BITS = {"fin": 0x01, "syn": 0x02, "rst": 0x04, "psh": 0x08, "ack": 0x10, "urg": 0x20}


class ForwardExtractor:
    def __init__(self, flow_timeout: float, max_flow_pkts: int, bucket_s: float = 5.0):
        self.flow_timeout = flow_timeout
        self.max_flow_pkts = max_flow_pkts
        self.bucket_s = bucket_s
        self.active: dict[tuple, FlowWindow] = {}
        self.rows: list[dict] = []
        self.src_rows: list[dict] = []
        self.src_active: dict[tuple, SourceWindow] = {}
        self.pkt_log: list[tuple] = []      # (t, src, size, iat_us, proto) for sequences
        self._sweep_every = 20_000
        self._pkts_seen = 0

    def _flush(self, key: tuple, fw: FlowWindow):
        sz_mean, sz_std, sz_min, sz_max = stats(list(fw.sizes))
        iat_mean, iat_std, iat_min, iat_max = stats(list(fw.iats))
        dur = fw.t_last - fw.t_first
        ent_mean, ent_max = (sum(fw.entropies) / len(fw.entropies),
                             max(fw.entropies)) if fw.entropies else (0.0, 0.0)
        ttl_mean, _, ttl_min, ttl_max = stats(list(fw.ttls))
        # retransmission-like behavior: identical (len, payload hash) repeats,
        # which a one-way link makes far more suspicious than in TCP (no ACK
        # negotiation explains them)
        uniq = len(set(fw.payload_hashes)) if fw.payload_hashes else fw.n
        retrans_frac = 1.0 - safe_div(min(uniq, fw.n), max(fw.n, 1))
        flags = {k: safe_div(v, fw.n) for k, v in fw.flags.items()}
        self.rows.append({
            "src": fw.src, "src_port": fw.sport, "dst": fw.dst, "dst_port": fw.dport,
            "proto": fw.proto,
            "n_packets": fw.n, "duration_s": round(dur, 6),
            "bytes_total": fw.bytes_sum,
            "pkt_size_mean": round(sz_mean, 3), "pkt_size_std": round(sz_std, 3),
            "pkt_size_min": sz_min, "pkt_size_max": sz_max,
            "iat_mean_us": round(iat_mean, 3), "iat_std_us": round(iat_std, 3),
            "iat_min_us": iat_min, "iat_max_us": iat_max,
            "rate_bytes_per_s": round(safe_div(fw.bytes_sum, dur), 3),
            "rate_pkts_per_s": round(safe_div(fw.n, dur), 3),
            "payload_entropy_mean": round(ent_mean, 4),
            "payload_entropy_max": round(ent_max, 4),
            "ttl_mean": round(ttl_mean, 2), "ttl_min": ttl_min, "ttl_max": ttl_max,
            "retrans_like_frac": round(retrans_frac, 4),
            **{f"flag_{k}_frac": round(v, 4) for k, v in flags.items()},
        })

    def feed(self, t: float, eth: dpkt.ethernet.Ethernet):
        ip = eth.data
        if not isinstance(ip, dpkt.ip.IP):
            return
        proto = ip.p
        src = ".".join(map(str, ip.src))
        dst = ".".join(map(str, ip.dst))
        sport = dport = 0
        payload = b""
        if proto == dpkt.ip.IP_PROTO_TCP and isinstance(ip.data, dpkt.tcp.TCP):
            sport, dport = ip.data.sport, ip.data.dport
            payload = ip.data.data
        elif proto == dpkt.ip.IP_PROTO_UDP and isinstance(ip.data, dpkt.udp.UDP):
            sport, dport = ip.data.sport, ip.data.dport
            payload = ip.data.data
        else:
            payload = bytes(ip.data)[:64]

        size = len(ip)                      # L3 size: stable across captures
        ent = shannon_entropy(payload[:256])
        ttl = ip.ttl
        phash = hashlib.md5(bytes([len(payload) & 0xFF]) + payload[:64]).hexdigest()[:8]

        # TCP flag accounting (works even though a diode never completes handshakes)
        fset = set()
        if proto == dpkt.ip.IP_PROTO_TCP and isinstance(ip.data, dpkt.tcp.TCP):
            fb = ip.data.flags
            for name, bit in TCP_FLAG_BITS.items():
                if fb & bit:
                    fset.add(name)

        key = (src, sport, dst, dport, proto)
        fw = self.active.get(key)
        if fw is None:
            fw = FlowWindow(key, t, size, ent, ttl, phash)
            self.active[key] = fw
        else:
            if (t - fw.t_last > self.flow_timeout) or fw.n >= self.max_flow_pkts:
                self._flush(key, fw)
                del self.active[key]
                fw = FlowWindow(key, t, size, ent, ttl, phash)
                self.active[key] = fw
            else:
                fw.add(t, size, ent, ttl, phash)
        for name in fset:
            fw.flags[name] += 1

        prev_t = getattr(self, "_prev_t", None)
        iat_us = int((t - prev_t) * 1e6) if prev_t is not None else 0
        self._prev_t = t
        self.pkt_log.append((t, src, size, iat_us, proto))

        # --- source-time-bucket view ---
        bkey = (src, int(t // self.bucket_s))
        sw = self.src_active.get(bkey)
        if sw is None:
            # flush the previous bucket of this src before starting a new one
            for k in [k2 for k2 in self.src_active if k2[0] == src and k2 != bkey]:
                self._flush_src(k2, self.src_active.pop(k2))
            sw = SourceWindow()
            self.src_active[bkey] = sw
        sw.add(t, size, dport, dst, proto, ent, ttl)

        self._pkts_seen += 1
        if self._pkts_seen % self._sweep_every == 0:
            self._sweep_stale(t)

    def _flush_src(self, bkey: tuple, sw: SourceWindow):
        iat_mean, iat_std, _, _ = stats(list(sw.iats))
        dur = (sw.t_last - sw.t_first) or self.bucket_s
        ent_mean = sum(sw.entropies) / len(sw.entropies) if sw.entropies else 0.0
        _, _, ttl_min, ttl_max = stats(list(sw.ttls))
        self.src_rows.append({
            "src": bkey[0], "bucket": bkey[1],
            "n_packets": sw.n, "bytes_total": sw.bytes_sum,
            "duration_s": round(dur, 6),
            "rate_pkts_per_s": round(safe_div(sw.n, dur), 3),
            "rate_bytes_per_s": round(safe_div(sw.bytes_sum, dur), 3),
            "iat_mean_us": round(iat_mean, 3), "iat_std_us": round(iat_std, 3),
            "n_dst_ports": len(sw.dst_ports), "n_dst_ips": len(sw.dst_ips),
            "port_spread": round(safe_div(len(sw.dst_ports), max(sw.n, 1)), 4),
            "proto_mask": int(sum(1 << p for p in sw.protos)),
            "payload_entropy_mean": round(ent_mean, 4),
            "ttl_min": ttl_min, "ttl_max": ttl_max,
        })

    def _sweep_stale(self, now: float):
        stale = [k for k, fw in self.active.items() if now - fw.t_last > self.flow_timeout]
        for k in stale:
            self._flush(k, self.active[k])
            del self.active[k]
        stale_src = [k for k, sw in self.src_active.items()
                     if now - (sw.t_last or now) > max(self.bucket_s * 4, 30)]
        for k in stale_src:
            self._flush_src(k, self.src_active.pop(k))

    def close(self):
        for key, fw in list(self.active.items()):
            self._flush(key, fw)
            del self.active[key]
        for bkey, sw in list(self.src_active.items()):
            self._flush_src(bkey, sw)
            del self.src_active[bkey]

# ---------------------------------------------------------------- sequence view

PROTO_CODE = {1: 0.0, 6: 1.0, 17: 2.0}     # icmp/tcp/udp -> small ordinal

def build_sequences(pkt_log, seq_len=50, stride=25, out_rows=None):
    """Sliding windows per source IP over (log size, log iat, proto)."""
    import numpy as np
    by_src: dict[str, list] = {}
    for t, src, size, iat_us, proto in pkt_log:
        by_src.setdefault(src, []).append((t, size, iat_us, proto))
    mats, metas = [], []
    for src, items in by_src.items():
        arr = [(math.log1p(sz), math.log1p(iat), PROTO_CODE.get(pr, pr % 7))
               for (_, sz, iat, pr) in items]
        for s in range(0, max(0, len(arr) - seq_len + 1), stride):
            win = arr[s:s + seq_len]
            m = np.asarray(win, dtype=np.float32)
            mats.append(m)
            metas.append({"src": src, "n_packets_in_stream": len(items),
                          "start_t": items[s][0]})
    if not mats:
        return None, None
    X = np.stack(mats)
    return X, metas

# ---------------------------------------------------------------- main

def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("pcap")
    ap.add_argument("--label", default="BENIGN")
    ap.add_argument("--slice-id", default=None)
    ap.add_argument("--out-dir", default="data/features")
    ap.add_argument("--flow-timeout", type=float, default=5.0)
    ap.add_argument("--max-flow-pkts", type=int, default=200)
    args = ap.parse_args()

    import pandas as pd

    pcap_path = Path(args.pcap)
    slice_id = args.slice_id or pcap_path.stem
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    ex = ForwardExtractor(args.flow_timeout, args.max_flow_pkts)
    n_bad = 0
    with open(pcap_path, "rb") as f:
        try:
            reader = dpkt.pcap.Reader(f)
        except ValueError:
            f.seek(0)
            reader = dpkt.pcapng.Reader(f)
        for ts, buf in reader:
            try:
                ex.feed(ts, dpkt.ethernet.Ethernet(buf))
            except Exception:                     # malformed frame: count, continue
                n_bad += 1
    ex.close()

    df = pd.DataFrame(ex.rows)
    df["label"] = args.label
    df["is_attack"] = int(args.label != "BENIGN")
    df["slice_id"] = slice_id
    tab_out = out_dir / f"flows_{slice_id}.parquet"
    df.to_parquet(tab_out, index=False)

    sdf = pd.DataFrame(ex.src_rows)
    sdf["label"] = args.label
    sdf["is_attack"] = int(args.label != "BENIGN")
    sdf["slice_id"] = slice_id
    src_out = out_dir / f"srcwin_{slice_id}.parquet"
    sdf.to_parquet(src_out, index=False)

    X, metas = build_sequences(ex.pkt_log)
    import numpy as np
    seq_out = out_dir / f"seqs_{slice_id}.npz"
    seq_stats = {}
    if X is not None:
        np.savez_compressed(seq_out, X=X,
                            labels=np.full(len(X), args.label),
                            is_attack=np.full(len(X), int(args.label != "BENIGN"), np.int8),
                            meta=json.dumps(metas))
        seq_stats = {"windows": int(len(X)), "dim": list(X.shape)}

    info = {
        "pcap": str(pcap_path), "slice_id": slice_id, "label": args.label,
        "flow_windows": int(len(df)), "src_windows": int(len(sdf)),
        "malformed_pkts": n_bad,
        "tabular": str(tab_out), "src_tabular": str(src_out), "sequences": seq_stats,
    }
    (out_dir / f"extract_{slice_id}.json").write_text(json.dumps(info, indent=2))
    print(json.dumps(info, indent=2))
    return 0


if __name__ == "__main__":
    sys.exit(main())
