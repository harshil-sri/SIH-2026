#!/usr/bin/env python3
"""SIH26145 — synthetic pcap generator for pipeline dry-runs.

Creates small labeled pcaps with REALISTIC PER-PACKET TIMESTAMPS so the whole
replay→capture→extract→train pipeline can be validated before the 50GB of
CICIDS2017 finishes downloading. Not used for final model training.

  data/synth/synth__benign__0.pcap      OT telemetry, varied cadence, bursts
  data/synth/synth__udp-flood__0.pcap   volumetric burst
  data/synth/synth__portscan-sim__0.pcap sequential port touching (many dst ports)
  data/synth/synth__covert-timing__0.pcap bits encoded in inter-packet gaps
"""
import random
from pathlib import Path

from scapy.all import Ether, IP, UDP, TCP, Raw, wrpcap


def ts_writer():
    pkts = []
    return pkts


def add(pkts, t, src, dst, sport, dport, payload, ttl=64, proto="udp", flags=0):
    eth = Ether(src=f"02:{random.randrange(16,255):02x}:aa:bb:cc:01",
                dst="ee:11:22:33:44:55")
    if proto == "udp":
        pkt = eth / IP(src=src, dst=dst, ttl=ttl) / UDP(sport=sport, dport=dport) / Raw(payload)
    else:
        pkt = eth / IP(src=src, dst=dst, ttl=ttl) / TCP(sport=sport, dport=dport,
                                                        flags=flags) / Raw(payload)
    pkt.time = t
    pkts.append(pkt)


def main() -> None:
    random.seed(7)
    out = Path("data/synth")
    out.mkdir(parents=True, exist_ok=True)
    MON = "10.200.0.2"
    t0 = 1756200000.0   # fixed epoch base; editcap/tcpreplay don't care

    # ---- benign telemetry -------------------------------------------------
    pkts, t = [], t0
    sensors = [{"ip": f"10.20.{i}.5", "period": random.uniform(0.3, 2.5),
                "next": t0 + i * 0.1, "val": 40.0} for i in range(8)]
    while t < t0 + 120:                       # 2 minutes
        for s in sensors:
            if t >= s["next"]:
                s["val"] += random.uniform(-1, 1)
                add(pkts, t, s["ip"], MON, 41000 + hash(s["ip"]) % 500,
                    9999, f"value={s['val']:.2f}".encode())
                if random.random() < 0.01:     # historian burst
                    for k in range(15):
                        add(pkts, t + k * 0.004, s["ip"], MON, 45000 + k, 9999,
                            b"backfill")
                s["next"] += s["period"] * random.uniform(0.75, 1.35)
        t += 0.05
    wrpcap(str(out / "synth__benign__0.pcap"), pkts)
    print(f"benign: {len(pkts)} packets / 120s")

    # ---- udp flood ---------------------------------------------------------
    pkts, t = [], t0
    while t < t0 + 20:
        for _ in range(random.randint(80, 160)):          # ~6k pps bursts
            add(pkts, t, "10.66.0.9", MON, random.randrange(20000, 60000),
                random.choice([53, 123, 1900]),
                bytes([random.randrange(256)] * random.randint(64, 400)), ttl=118)
            t += 0.0002
        t += random.uniform(0.05, 0.2)
    wrpcap(str(out / "synth__udp-flood__0.pcap"), pkts)
    print(f"udp flood: {len(pkts)} packets / 20s")

    # ---- portscan-sim ------------------------------------------------------
    pkts, t = [], t0
    for port in range(1000, 1300):                         # sequential sweep
        t += random.uniform(0.004, 0.03)
        add(pkts, t, "10.66.0.66", MON, random.randrange(40000, 60000),
            port, b"", ttl=127, proto="tcp", flags=0x02)   # lone SYNs
    wrpcap(str(out / "synth__portscan-sim__0.pcap"), pkts)
    print(f"portscan-sim: {len(pkts)} packets")

    # ---- covert timing channel --------------------------------------------
    pkts, t = [], t0
    bits = "".join(f"{b:08b}" for b in b"HIDDEN")
    for i, bit in enumerate(bits * 12):
        t += (0.018 if bit == "0" else 0.075) * random.uniform(0.92, 1.08)
        add(pkts, t, "10.20.3.5", MON, 41003, 9999,
            bytes([random.randrange(256)]), ttl=64)
    wrpcap(str(out / "synth__covert-timing__0.pcap"), pkts)
    print(f"covert timing: {len(pkts)} packets")


if __name__ == "__main__":
    main()
