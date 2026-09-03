#!/usr/bin/env python3
"""SIH26145 — Live monitor-side pipeline: receive one-way traffic, window it,
push feature rows to the scoring API, print alerts.

This is what would sit behind the tap of a real diode deployment: it only ever
recvfrom()s (transport-layer one-way), aggregates per-source time buckets
using the SAME feature semantics as the offline extractor, and posts each
closed bucket to FastAPI /score.

Run inside ns-monitor:
  sudo ip netns exec ns-monitor .venv/bin/python serving/live_pipeline.py \
      --window-s 3 --api http://10.0.2.15:8200     # host-reachable API address
"""
import argparse
import json
import math
import socket
import sys
import time
import urllib.request
from collections import deque
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
PROTO_CODE = {1: 0.0, 6: 1.0, 17: 2.0}


def entropy(b: bytes) -> float:
    if not b:
        return 0.0
    counts = [0] * 256
    for x in b:
        counts[x] += 1
    n = len(b)
    return -sum((c / n) * math.log2(c / n) for c in counts if c)


class Bucket:
    __slots__ = ("n", "b", "ports", "ips", "iats", "ents", "ttls", "t0", "tl")

    def __init__(self):
        self.n = self.b = 0
        self.ports, self.ips = set(), set()
        self.iats = deque(maxlen=512)
        self.ents = deque(maxlen=256)
        self.ttls = deque(maxlen=256)
        self.t0 = None
        self.tl = None

    def add(self, t, size, dport, dip, ent, ttl):
        if self.t0 is None:
            self.t0 = t
        elif len(self.iats) < self.iats.maxlen:
            self.iats.append(t - self.tl)
        self.tl = t
        self.n += 1
        self.b += size
        if len(self.ports) < 2048:
            self.ports.add(dport)
        if len(self.ips) < 256:
            self.ips.add(dip)
        if len(self.ents) < self.ents.maxlen:
            self.ents.append(ent)
            self.ttls.append(ttl)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--bind-port", type=int, default=9999)
    ap.add_argument("--window-s", type=float, default=3.0)
    ap.add_argument("--api", default="http://127.0.0.1:8200")
    args = ap.parse_args()

    rx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    rx.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 8 << 20)
    rx.bind(("0.0.0.0", args.bind_port))
    rx.settimeout(0.25)
    print(f"[live] receiving on :{args.bind_port}, {args.window_s}s buckets -> {args.api}")

    active: dict[str, Bucket] = {}
    last_flush = time.time()
    prev_t = {}
    total = alerted = 0

    def flush(src: str, b: Bucket):
        nonlocal total, alerted
        dur = max((b.tl - b.t0), args.window_s * 0.9)
        iats = list(b.iats)
        feat = {
            "src_o12": -1, "src_o4": -1,
            "n_packets": float(b.n),
            "bytes_total": float(b.b),
            "duration_s": round(dur, 3),
            "rate_pkts_per_s": round(b.n / dur, 3),
            "rate_bytes_per_s": round(b.b / dur, 3),
            "iat_mean_us": round(sum(iats) / len(iats) * 1e6, 2) if iats else 0.0,
            "iat_std_us": (sum((x - sum(iats) / len(iats)) ** 2 for x in iats)
                           / len(iats)) ** 0.5 * 1e6 if iats else 0.0,
            "n_dst_ports": float(len(b.ports)),
            "n_dst_ips": float(len(b.ips)),
            "port_spread": round(len(b.ports) / max(b.n, 1), 4),
            "payload_entropy_mean": round(sum(b.ents) / len(b.ents), 4) if b.ents else 0.0,
            "ttl_min": min(b.ttls) if b.ttls else 0.0,
            "ttl_max": max(b.ttls) if b.ttls else 0.0,
        }
        body = json.dumps({"features": feat}).encode()
        try:
            req = urllib.request.Request(f"{args.api}/score", data=body,
                                         headers={"Content-Type": "application/json"})
            resp = json.loads(urllib.request.urlopen(req, timeout=5).read())
        except Exception as e:                          # noqa: BLE001
            print(f"[live] api error: {e}")
            return
        total += 1
        if resp["verdict"] != "OK":
            alerted += 1
            print(f"  ⚠ {resp['verdict']:<8} score={resp['threat_score']:.2f} "
                  f"{src}: {' | '.join(resp['reasons'])} [{resp['latency_ms']}ms]")

    while True:
        now = time.time()
        try:
            data, addr = rx.recvfrom(65535)
        except socket.timeout:
            data = None
        if now - last_flush >= args.window_s:
            cur_bucket = int(now // args.window_s)
            for src in list(active):
                if int(active[src].t0 // args.window_s) < cur_bucket - 1:
                    flush(src, active.pop(src))
            last_flush = now
        if data is None:
            continue
        t = time.time()
        src = addr[0]
        ent = entropy(data[:128])
        b = active.setdefault(src, Bucket())
        b.add(t, len(data), 0, "", ent, 64)

    # unreachable


if __name__ == "__main__":
    main()
