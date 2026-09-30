#!/usr/bin/env python3
"""SIH26145 — Volumetric / spoofed-source flood detector.

Looks at the DISTRIBUTION OF SOURCE IPs inside each monitor-side time window.
A real host generates traffic from a small, stable set of sources; an attacker
whose packets carry spoofed source addresses makes the source set suddenly
large and evenly spread. The per-window source entropy is the tell.

Requires an L3 tap (raw socket) — the UDP relay collapses all traffic onto one
transport source, so this detector is fed by the tap path only. When no tap is
up it returns no evidence and quietly does nothing (honest degrade).
"""
from __future__ import annotations

import os
from collections import Counter

from detectors.common import entropy_bits, clip

NAME = "volumetric"
THREAT_CLASS = "volumetric"

# below this many distinct sources nothing is worth scoring (noise floor)
MIN_SOURCES = 8
# scale so a realistic spoofed flood (thousands of sources) reaches ~1.0
SOURCE_SCALE = 100
# DOI NOTHING with churn alone — real internet windows churn up to ~0.83
# (p99 of the CICIDS benign trace) and ONE of them has 1356 distinct sources.
# The discriminator for a spoofed/rotating flood is the MASS OF EXACTLY-ONCE
# sources (once_seen = n_src_squared churn): benign fan-in of one-shots peaks
# near ~1125; a flood is thousands by construction. So we fire only on
#   - once_seen >= MASS_ONCE            (a genuine large rotation), or
#   - churn saturates near 1.0          (a fire-and-forget one-shot sweep)
MASS_ONCE = 2000
CHURN_SAT = 0.95

# High-VOLUME fallback: on some host stacks (notably WSL2 / NAT) the kernel
# rewrites or drops spoofed source addresses, so a real flood arrives collapsed
# onto a handful of sources and the fan-out signature above never triggers —
# the flood then scores as benign. A volumetric flood is fundamentally about
# VOLUME, so also fire when a window carries flood-level packet volume that is
# overwhelmingly UDP. Benign windows never approach this: measured benign peak
# is a few hundred packets/window, and benign traffic is not ~all-UDP.
FLOOD_PACKETS = 1500      # packets in one window (3s buckets -> 500+ pkts/s)
UDP_FLOOD_FRAC = 0.9      # a UDP flood is ~entirely UDP


class VolumetricDetector:
    def __init__(self) -> None:
        self.window_id: int | None = None
        self._held: dict[int, dict] = {}
        self.sources: Counter = Counter()
        self.n_packets = 0
        self.n_udp = 0

    def on_event(self, ev: dict) -> None:
        if not ev.get("tap"):
            return  # relay-only stream: transport source is always the relay
        wid = ev.get("window_id")
        if self.window_id is None:
            self.window_id = wid
        elif wid != self.window_id:
            # The tap feeds continuously while the coordinator flushes whole
            # windows from another thread; a window transition can therefore
            # arrive BEFORE we get flushed. Fold the just-closed window into a
            # held row (emitted on its flush) instead of exploding — a live
            # detector has to survive boundary races silently.
            row = self._score(reset=False)
            if row:
                self._held[self.window_id] = row
            self.window_id = wid
            self.sources = Counter()
            self.n_packets = 0
            self.n_udp = 0
        self.sources[ev.get("src", "")] += 1
        self.n_packets += 1
        if ev.get("proto") == 17:
            self.n_udp += 1

    def flush_window(self, t: float, window_id: int) -> dict | None:
        if window_id in self._held:
            return self._held.pop(window_id)
        if self.window_id is None or self.window_id != window_id:
            # no tap traffic this window -> nothing to say
            return None
        return self._score(reset=True)

    def _score(self, reset: bool) -> dict | None:
        items = list(self.sources.items())   # snapshot: tap thread feeds live
        n_src = len(items)
        n_packets = sum(c for _, c in items)
        once = sum(1 for _, c in items if c == 1)
        churn = once / n_src if n_src else 0.0
        n_udp_frac = self.n_udp / n_packets if n_packets else 0.0
        if os.environ.get("VOL_DEBUG"):
            print(f"[volumetric] n_src={n_src} n_pkts={n_packets} once={once} "
                  f"churn={churn:.2f} udp={n_udp_frac:.2f}", flush=True)
        if n_packets <= 0:
            if reset:
                self._reset()
            return None
        # Path A — source fan-out: a big enough ROTATION (mass of one-shot
        # sources) or a saturation sweep (almost every source appears exactly
        # once). Ordinary internet/LAN windows never get here: CICIDS benign
        # peak one-shot fan-in is ~1125 and only flood traffic saturates churn.
        fanout = n_src >= MIN_SOURCES and (once >= MASS_ONCE or churn >= CHURN_SAT)
        # Path B — high-volume UDP flood that did NOT fan out (spoofing stripped
        # by the host stack, e.g. WSL2). Volume + near-total UDP is the tell.
        volume = n_packets >= FLOOD_PACKETS and n_udp_frac >= UDP_FLOOD_FRAC
        if not (fanout or volume):
            if reset:
                self._reset()
            return None
        h = entropy_bits(c for _, c in items)
        norm = h / (n_src.bit_length() - 1) if n_src > 1 else 0.0  # h/log2(n)
        spread = clip(n_src / SOURCE_SCALE)
        churn_term = (churn - 0.9) / 0.1 if churn >= CHURN_SAT else 0.0
        score = clip(0.45 * norm + 0.35 * spread + 0.20 * churn_term)
        if volume and not fanout:
            # volume-dominant flood: scale the score by how far the window
            # exceeds the flood floor so a bigger flood reads hotter.
            score = clip(max(score, 0.70 + 0.25 * clip(
                (n_packets - FLOOD_PACKETS) / (4 * FLOOD_PACKETS))))
            why = (f"{n_packets} packets in-window ({n_udp_frac:.0%} UDP) from "
                   f"{n_src} source(s) — flood-level volume (source spoofing not "
                   f"observable on this host stack)")
        else:
            why = (f"{once} one-shot sources over a {n_src}-source window "
                   f"(churn {churn:.0%}, entropy {h:.2f} bits) — the rotating/"
                   "spoofed-source signature of a source-fan-out flood")
        row = {
            "detector": NAME,
            "threat_class": THREAT_CLASS,
            "score": round(score, 3),
            "confidence": round(clip(score), 3),
            "features": {
                "n_distinct_sources": n_src,
                "n_packets": n_packets,
                "source_entropy_bits": round(h, 2),
                "normalized_entropy": round(norm, 2),
                "source_churn_fraction": round(churn, 3),
                "one_shot_source_mass": once,
                "udp_fraction": round(n_udp_frac, 2),
            },
            "why": why,
        }
        if reset:
            self._reset()
        return row

    def _reset(self) -> None:
        self.window_id = None
        self.sources = Counter()
        self.n_packets = 0
        self.n_udp = 0


if __name__ == "__main__":
    import random
    d = VolumetricDetector()
    # benign: a couple of stable sources
    for i in range(200):
        d.on_event({"tap": True, "window_id": 0, "src": "10.0.0.1", "proto": 17})
    for i in range(150):
        d.on_event({"tap": True, "window_id": 0, "src": "10.0.0.6", "proto": 17})
    print("benign:", d.flush_window(0.0, 0))
    # spoofed flood: thousands of random sources
    rng = random.Random(7)
    for i in range(20000):
        s = "%d.%d.%d.%d" % tuple(rng.randrange(1, 255) for _ in range(4))
        d.on_event({"tap": True, "window_id": 1, "src": s, "proto": 17})
    print("spoofed:", d.flush_window(1.0, 1))