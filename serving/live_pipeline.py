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
import os
import socket
import sys
import threading
import time
import urllib.request
from collections import deque
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from detectors import DetectorCoordinator              # noqa: E402
from detectors import scan as scan_detector            # noqa: E402  (bucket-feature scan shape)
PROTO_CODE = {1: 0.0, 6: 1.0, 17: 2.0}
PROTO_UDP = 17            # the one-way relay carries UDP datagrams
SEQ_LEN = 50              # must match extract_features.build_sequences seq_len
MIN_SEQ = 8               # below this a window is too short to score usefully


def entropy(b: bytes) -> float:
    if not b:
        return 0.0
    counts = [0] * 256
    for x in b:
        counts[x] += 1
    n = len(b)
    return -sum((c / n) * math.log2(c / n) for c in counts if c)


class Bucket:
    __slots__ = ("n", "b", "ports", "ips", "iats", "ents", "ttls", "protos",
                 "t0", "tl", "seq")

    def __init__(self):
        self.n = self.b = 0
        self.ports, self.ips = set(), set()
        self.protos = set()
        self.iats = deque(maxlen=512)
        self.ents = deque(maxlen=256)
        self.ttls = deque(maxlen=256)
        self.t0 = None
        self.tl = None
        # Per-packet rows for the autoencoder, in the SAME order and units as
        # extraction/extract_features.py SEQ_FEATURES:
        #   (log1p(size), log1p(iat_us), proto_code, payload_entropy)
        # Without this the live path posted no `sequence` at all, so the novel
        # threat half of the detector never contributed to a live demo score.
        self.seq = deque(maxlen=SEQ_LEN)

    def add(self, t, size, dport, dip, ent, ttl, proto=PROTO_UDP):
        iat_us = 0.0
        if self.t0 is None:
            self.t0 = t
        else:
            iat_us = max(0.0, (t - self.tl) * 1e6)
            if len(self.iats) < self.iats.maxlen:
                self.iats.append(t - self.tl)
        self.tl = t
        self.n += 1
        self.b += size
        if len(self.ports) < 2048:
            self.ports.add(dport)
        if len(self.ips) < 256:
            self.ips.add(dip)
        if len(self.protos) < 8:
            self.protos.add(proto)
        if len(self.ents) < self.ents.maxlen:
            self.ents.append(ent)
            self.ttls.append(ttl)
        self.seq.append((math.log1p(size), math.log1p(iat_us),
                         PROTO_CODE.get(proto, proto % 7), ent))

    def sequence(self) -> list[list[float]] | None:
        """Left-pad to SEQ_LEN with the first row; None if too short to be useful."""
        rows = list(self.seq)
        if len(rows) < MIN_SEQ:
            return None
        if len(rows) < SEQ_LEN:
            rows = [rows[0]] * (SEQ_LEN - len(rows)) + rows
        return [list(map(float, r)) for r in rows]


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--bind-port", type=int, default=9999)
    ap.add_argument("--window-s", type=float, default=5.0,
                    help="bucket seconds; must match extraction BUCKET_S for model features")
    ap.add_argument("--api", default="http://127.0.0.1:8200")
    ap.add_argument("--tap-dev", default="",
                    help="monitor-side veth for the L3 raw tap (spoofed-source "
                         "detection / TLS prototype). Requires root.")
    args = ap.parse_args()

    rx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    rx.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 8 << 20)
    rx.bind(("0.0.0.0", args.bind_port))
    rx.settimeout(0.25)
    print(f"[live] receiving on :{args.bind_port}, {args.window_s}s buckets -> {args.api}")

    active: dict[str, Bucket] = {}
    last_flush = time.time()
    total = alerted = 0
    coord = DetectorCoordinator()

    def flush(src: str, b: Bucket, dets: tuple = ()):
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
            "proto_mask": int(sum(1 << p for p in b.protos)),
            "payload_entropy_mean": round(sum(b.ents) / len(b.ents), 4) if b.ents else 0.0,
            "ttl_min": min(b.ttls) if b.ttls else 0.0,
            "ttl_max": max(b.ttls) if b.ttls else 0.0,
        }
        scan_row = scan_detector.on_event(feat)
        dets = list(dets or ())
        if scan_row:
            dets.append(scan_row)
        body = json.dumps({"features": feat, "sequence": b.sequence(),
                           "flow_id": f"{src}* -> relay/UDP",
                           "win_pkts": b.n, "win_bytes": b.b,
                           "detectors": dets}).encode()
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

    def tap_loop():
        """Raw L3 receiver on the monitor-side veth: the observation point of a
        real diode's monitor port. When present it is the AUTHORITATIVE source
        for both feature buckets and detector evidence, because only full frames
        carry the ports / TTL / sizes / protocols the models were trained on.
        Runs only when --tap-dev is given."""
        try:
            import dpkt
            raw = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                                socket.htons(0x0003))
            # The default raw-socket buffer (~212 KB) overflows under the
            # demo's 1000+ pps injections while we dpkt-parse each frame — the
            # kernel then silently DROPS the tail of a burst (measured: 2.9k of
            # 8.6k spoofed flood frames reached the bucket; a 1.2 kpps portscan
            # stream was starved ENTIRELY). A large buffer lets the kernel keep
            # the burst while the reader catches up instead of discarding it;
            # setup_diode.sh raises net.core.rmem_max so this isn't clamped.
            for size_mib in (16, 8, 4):
                try:
                    raw.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF,
                                   size_mib << 20)
                except OSError:
                    continue
                break
            raw.bind((args.tap_dev, 0))
            got = raw.getsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF)
            print(f"[live] tap up on {args.tap_dev} (authoritative feature source) "
                  f"rcvbuf={got}")
            nf = t0 = 0
            while True:
                frame = raw.recv(65535)
                nf += 1
                t = time.time()
                if t - t0 >= 5.0:
                    print(f"[live] tap ~{nf / max(t - t0, 1e-6):.0f} f/s "
                          f"({nf} total)", flush=True)
                    nf, t0 = 0, t
                try:
                    eth = dpkt.ethernet.Ethernet(frame)
                    ip = eth.data
                    if not isinstance(ip, dpkt.ip.IP):
                        continue
                    src = ".".join(map(str, ip.src))
                    dst_ip = ".".join(map(str, ip.dst))
                    payload = b""
                    dport = 0
                    proto = ip.p
                    if proto == 17 and isinstance(ip.data, dpkt.udp.UDP):
                        dport, payload = ip.data.dport, bytes(ip.data.data)
                    elif proto == 6 and isinstance(ip.data, dpkt.tcp.TCP):
                        dport, payload = ip.data.dport, bytes(ip.data.data)
                    elif proto == 1:
                        payload = bytes(ip.data)
                    t = time.time()
                    ent = entropy(payload[:128])
                    b = active.setdefault(src, Bucket())
                    b.add(t, len(ip), dport, dst_ip, ent, ip.ttl, proto)
                    coord.feed({"t": t,
                                "window_id": int(t // args.window_s),
                                "src": src, "dst_ip": dst_ip, "dst_port": dport,
                                "proto": proto, "size": len(ip), "payload": payload,
                                "tap": True})
                except Exception:                        # noqa: BLE001
                    continue
        except Exception as e:                          # noqa: BLE001
            print(f"[live] tap unavailable ({e}) — continuing relay-only")

    tap_on = bool(args.tap_dev)
    if tap_on:
        threading.Thread(target=tap_loop, daemon=True).start()

    while True:
        now = time.time()
        try:
            data, addr = rx.recvfrom(65535)
        except socket.timeout:
            data = None
        if now - last_flush >= args.window_s:
            cur_bucket = int(now // args.window_s)
            window_rows = coord.flush(now, cur_bucket) or []
            # window-level evidence (volumetric/beacon/exfil/dns/tls) is
            # attached ONCE per window, otherwise every per-source bucket would
            # re-alert the same flood window a dozen times.
            stale = [s for s in list(active)
                     if int(active[s].t0 // args.window_s) < cur_bucket - 1]
            # src-bound window evidence (beacon/c2) names the bucket it
            # describes. If that bucket is still in active, force-flush it NOW
            # with its own rows — accurate attribution instead of either
            # mis-attaching to "whichever host went stale first" (the WS-1
            # soak's exact complaint) or dropping the evidence until some
            # later staleness lottery (the demo's beacon flake).
            target = None
            for r in window_rows:
                s = r.get("src")
                if s and s in active:
                    target = s
                    break
            # window-LEVEL evidence (volumetric flood, dns/tls aggregates)
            # carries NO src: it describes the whole window, not one host. A
            # spoofed flood in particular fans out over hundreds of one-shot
            # buckets that are all still FRESH this cycle, so `stale` is empty
            # and there is no natural carrier — the old code then dropped the
            # strand silently (the volumetric-never-fires bug). Ride it out on
            # the busiest active bucket so the evidence still reaches /score;
            # the detector row's own features/why carry the real aggregate
            # (n_distinct_sources, one-shot mass), so attribution stays honest.
            srcless = any(not r.get("src") for r in window_rows)
            if target in active:
                stale = stale + [target] if target not in stale else stale
            elif target is None and srcless and active:
                target = max(active, key=lambda s: active[s].n)
                stale = stale + [target] if target not in stale else stale
            elif target is None and any(r.get("src") for r in window_rows) and not stale:
                # src-bound window evidence (beacon/c2) whose named bucket is
                # already gone: the detector keeps a multi-minute history so it
                # re-surfaces; never re-attach it to some other stale host (that
                # is the WS-1 mis-attribution). Safe to skip this window.
                target = "__skip__"
            if os.environ.get("PIPE_DEBUG"):
                print(f"[live] flush win={cur_bucket} stale={stale} "
                      f"target={target} "
                      f"wrows={[(r.get('detector'), r.get('src')) for r in window_rows]}")
            for src in stale:
                b = active.pop(src)
                rows = tuple(window_rows) if src == target else ()
                # Suppress trivial per-source windows. A spoofed-source flood
                # creates THOUSANDS of one-shot buckets (one per forged IP);
                # scoring each as its own window buries the real detections
                # under a wall of duplicate OK rows (the "8000 windows, almost
                # all OK" symptom). A bucket with fewer than MIN_SEQ packets
                # carries no usable AE sequence, so unless it is the one holding
                # detector evidence (target) there is nothing to score — drop
                # it. Evidence-carrying and substantive buckets always flush.
                if not rows and b.n < MIN_SEQ:
                    continue
                flush(src, b, rows)
            last_flush = now
        if data is None or tap_on:
            # with the tap active the relay datagrams are the same payloads the
            # tap already counted — feeding them again would double every bucket
            continue
        t = time.time()
        src = addr[0]
        ent = entropy(data[:128])
        b = active.setdefault(src, Bucket())
        b.add(t, len(data), 0, "", ent, 64)
        coord.feed({"t": t, "window_id": int(t // args.window_s), "src": src,
                    "proto": PROTO_UDP, "size": len(data), "payload": data,
                    "tap": False})

    # unreachable


if __name__ == "__main__":
    main()
