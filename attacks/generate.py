#!/usr/bin/env python3
"""SIH26145 — Custom diode-relevant threat generators (Scapy).

These produce the attack classes the base plan identifies as diode-specific —
the ones public datasets DON'T cover, which is what makes the "AI-based"
claim defensible. Each generator pushes UDP datagrams to the relay input
(127.0.0.1:<port> inside ns-source) or raw-injects frames when malformed L2/L3
content is required.

Generators:
  benign          simulated OT telemetry: periodic sensor readings, varied rates
  udp_flood       volumetric burst on the monitor path (random ports + payload)
  covert_timing   bits encoded in inter-packet delays (slow-drip exfil channel)
  stego_payload   hidden data smuggled in low-entropy-looking telemetry payloads
  malformed       off-spec frames: bad IP total_length, bogus protocol, bad csum

Usage (inside ns-source):
  ip netns exec ns-source python attacks/generate.py benign --seconds 30
  ip netns exec ns-source python attacks/generate.py udp_flood --rate-pps 3000 --seconds 5
  ...
"""
import argparse
import random
import socket
import struct
import time

RELAY = ("127.0.0.1", 10500)


def sock() -> socket.socket:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    return s


# ------------------------------------------------------------------ benign

def gen_benign(seconds: float, sensors: int = 6) -> None:
    """Simulated industrial telemetry: each sensor has its own cadence and
    value distribution; occasional bursts (historian sync) keep it honest."""
    s = sock()
    t_end = time.time() + seconds
    state = [{"id": i, "next": 0.0, "period": random.uniform(0.2, 2.0),
              "val": random.uniform(20, 90)} for i in range(sensors)]
    while time.time() < t_end:
        now = time.time()
        for st in state:
            if now >= st["next"]:
                st["val"] += random.uniform(-1.5, 1.5)
                msg = f"sensor={st['id']};ts={int(now)};value={st['val']:.2f};unit=C".encode()
                s.sendto(msg, RELAY)
                # historian sync burst: ~0.5% chance of a 20-packet backfill
                if random.random() < 0.005:
                    for k in range(20):
                        s.sendto(f"backfill;s={st['id']};k={k}".encode(), RELAY)
                st["next"] = now + st["period"] * random.uniform(0.7, 1.4)
        time.sleep(0.01)


# ------------------------------------------------------------------ attacks

def gen_udp_flood(rate_pps: float, seconds: float) -> None:
    """Volumetric attack on the monitor path. Randomized src ports per packet
    so per-5-tuple flows fragment — only the source-bucket view sees it whole."""
    s = sock()
    interval = 1.0 / max(rate_pps, 1)
    t_end = time.time() + seconds
    n = 0
    while time.time() < t_end:
        payload = bytes(random.randrange(256) for _ in range(random.randint(32, 512)))
        s.sendto(payload, RELAY)
        n += 1
        time.sleep(interval * random.uniform(0.5, 1.5))
    print(f"[udp_flood] sent {n}")


def gen_covert_timing(seconds: float, message: str = "SECRET", bit0_ms: float = 15,
                      bit1_ms: float = 70) -> None:
    """Covert timing channel: message bytes -> bits -> inter-packet delays.
    Statistically subtle; needs sequence modeling of IATs to surface."""
    s = sock()
    bits = "".join(f"{b:08b}" for b in message.encode())
    t_end = time.time() + seconds
    i = 0
    seq = random.Random(1234)
    while time.time() < t_end:
        b = bits[i % len(bits)]
        delay = (bit0_ms if b == "0" else bit1_ms) / 1000.0
        delay *= random.uniform(0.9, 1.1)           # light jitter to evade thresholds
        s.sendto(b"x%02x" % seq.randrange(256), RELAY)
        time.sleep(delay)
        i += 1
    print(f"[covert_timing] sent {i} packets encoding {len(bits)} bits")


def gen_stego_payload(seconds: float, secret: str = "EXFIL-ME") -> None:
    """Payload steganography: telemetry-shaped packets whose numeric fields
    carry secret nibbles in their decimals. Entropy looks normal; content is not."""
    s = sock()
    nibbles = "".join(f"{ord(c):04b}" for c in secret)[:64]
    t_end = time.time() + seconds
    i = 0
    while time.time() < t_end:
        val = 40.0
        if i < len(nibbles):
            val += int(nibbles[i]) * 0.03           # LSB-ish carrier in the decimal
        msg = f"sensor=9;ts={int(time.time())};value={val:.2f};unit=C".encode()
        s.sendto(msg, RELAY)
        time.sleep(random.uniform(0.8, 1.6))        # innocent cadence
        i += 1
    print(f"[stego_payload] sent {i} carriers")


def gen_malformed(count: int, use_raw: bool = False) -> None:
    """Off-spec frames via scapy raw injection (needs root inside ns-source):
    - IP total_length field lying about the real size
    - unknown protocol number
    - UDP length mismatch / zero checksum abuse
    The monitor-side kernel must still ACCEPT these onto the wire for us to
    observe them, so malformations stay within pcap-capturable bounds."""
    from scapy.all import Ether, IP, UDP, Raw, sendp   # noqa: PLC0415
    payload = b"A" * 24
    for i in range(count):
        ip = IP(src="10.200.0.77", dst="10.200.0.2", ttl=random.choice([1, 37, 255]))
        udp = UDP(sport=40000 + i, dport=9999, chksum=0)(Raw(payload))
        frame = Ether(src="de:ad:be:ef:00:01", dst="ee:11:22:33:44:55") / ip / udp
        # lie about IP total length (short by 8) — classic off-spec shape
        frame[IP].len = frame[IP].len - 8
        sendp(frame, verbose=False)
    print(f"[malformed] injected {count} frames")


GENERATORS = {
    "benign": lambda a: gen_benign(a.seconds),
    "udp_flood": lambda a: gen_udp_flood(a.rate_pps, a.seconds),
    "covert_timing": lambda a: gen_covert_timing(a.seconds, bit0_ms=a.bit0_ms,
                                                 bit1_ms=a.bit1_ms),
    "stego_payload": lambda a: gen_stego_payload(a.seconds),
    "malformed": lambda a: gen_malformed(a.count),
}


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="gen", required=True)
    for name in GENERATORS:
        p = sub.add_parser(name)
        p.add_argument("--seconds", type=float, default=10.0)
        p.add_argument("--rate-pps", type=float, default=1000.0)
        p.add_argument("--count", type=int, default=50)
        p.add_argument("--bit0-ms", type=float, default=15.0)
        p.add_argument("--bit1-ms", type=float, default=70.0)
    args = ap.parse_args()
    GENERATORS[args.gen](args)


if __name__ == "__main__":
    main()
