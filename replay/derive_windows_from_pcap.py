#!/usr/bin/env python3
"""SIH26145 — Derive ATTACK WINDOWS IN PCAP TIME BASE (ground truth for slicing).

Problem: CICIDS2017 CSV timestamps are internally inconsistent (12h-vs-24h
clock in several files, e.g. Friday-afternoon writes 15:30 as "3:30"), so
editcap cuts made straight from CSV times land at wrong positions.

Fix: locate the attacks inside the pcap itself.
  1. From data/windows.json (CSV-derived) take each label's source IPs.
  2. ONE tcpdump pass per day pcap collects timestamps of every attacker-IP
     packet (selective BPF -> fast enough even for 12GB files).
  3. Cluster each IP's packet times into bursts (gap >= GAP_S separates).
  4. Assign bursts to labels: a label's CSV window is ambiguous among offsets
     {0, +12h, -12h}; score each candidate against bursts, keep best match.
  5. Emit data/windows_pcap.json with windows in pcap-relative epoch terms +
     docs/ATTACK_WINDOWS.md human-readable table.

Usage: python replay/derive_windows_from_pcap.py [--pcap-dir datasets/raw]
"""
import argparse
import json
import subprocess
from datetime import datetime
from pathlib import Path

GAP_S = 120          # silence gap separating two attack bursts
OFFSET_CANDIDATES_H = (0, 12, -12)


def pcap_bounds(pcap: Path) -> tuple[float, float]:
    """(first,last) packet epochs; raises if the file is incomplete/unreadable."""
    out = subprocess.run(["capinfos", "-a", "-e", str(pcap)],
                         capture_output=True, text=True, check=True).stdout
    vals = []
    for key in ("First packet time:", "Last packet time:"):
        line = next(l for l in out.splitlines() if l.startswith(key))
        vals.append(_parse_capinfos_dt(line.split(":", 1)[1]))
    return vals[0], vals[1]


def _parse_capinfos_dt(val: str) -> float:
    for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S"):
        try:
            return datetime.strptime(val.strip(), fmt).timestamp()
        except ValueError:
            continue
    raise ValueError(f"cannot parse capinfos time {val!r}")


def collect_attacker_times(pcap: Path, ips: set[str]) -> dict[str, list[float]]:
    """One tcpdump pass; return {ip: [packet epochs]} for the given source IPs."""
    bpf = " or ".join(f"src host {ip}" for ip in sorted(ips))
    proc = subprocess.Popen(["tcpdump", "-n", "-r", str(pcap), bpf, "-tt"],
                            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
    times: dict[str, list[float]] = {ip: [] for ip in ips}
    assert proc.stdout
    for line in proc.stdout:
        parts = line.split()
        if len(parts) < 2:
            continue
        try:
            ts = float(parts[0])
        except ValueError:
            continue
        src = parts[2].split(":")[0].split(".")[0:4]
        if len(src) == 4:
            ip = ".".join(src)
            if ip in times and len(times[ip]) < 4_000_000:
                times[ip].append(ts)
    proc.wait()
    return times


def bursts(ts_list: list[float]) -> list[tuple[float, float]]:
    """Merge packet times into [start,end] bursts split on GAP_S silence."""
    if not ts_list:
        return []
    ts = sorted(ts_list)
    out, s, prev = [], ts[0], ts[0]
    for t in ts[1:]:
        if t - prev > GAP_S:
            out.append((s, prev))
            s = t
        prev = t
    out.append((s, prev))
    return out


def overlap(a0, a1, b0, b1) -> float:
    return max(0.0, min(a1, b1) - max(a0, b0))


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--pcap-dir", default="datasets/raw")
    ap.add_argument("--windows", default="data/windows.json")
    ap.add_argument("--out", default="data/windows_pcap.json")
    args = ap.parse_args()

    db = json.loads(Path(args.windows).read_text())
    result: dict[str, dict] = {}

    for pcap_name, entry in db.items():
        pcap = Path(args.pcap_dir) / pcap_name
        if not pcap.exists():
            print(f"!! {pcap} missing, skipped")
            continue
        t_start, t_end = None, None
        try:
            t_start, t_end = pcap_bounds(pcap)
        except (subprocess.CalledProcessError, StopIteration, ValueError):
            print(f"!! {pcap} unreadable/incomplete (download still running?) — skipped")
            continue
        print(f"\n=== {pcap_name}  ({datetime.fromtimestamp(t_start):%Y-%m-%d %H:%M} + "
              f"{(t_end-t_start)/3600:.1f}h) ===")

        # gather every attacker IP mentioned by any window of this day
        all_ips = {ip for w in entry["windows"] for ip in w["src_ips"] if ip}
        att_times = collect_attacker_times(pcap, all_ips) if all_ips else {}

        new_windows = []
        for w in entry["windows"]:
            dur_csv = w["end"] - w["start"]
            candidates = []
            for ip in w["src_ips"]:
                for b0, b1 in bursts(att_times.get(ip, [])):
                    candidates.append((b0, b1))
            # score: for each offset, total overlap of shifted csv window w/ bursts
            best, best_score = None, -1.0
            for off_h in OFFSET_CANDIDATES_H:
                off = off_h * 3600
                s0, s1 = w["start"] + off, w["end"] + off
                score = sum(overlap(s0, s1, c0, c1) for c0, c1 in candidates)
                if score > best_score:
                    best, best_score = (off, s0, s1), score
            off, s0, s1 = best

            # refine: intersect matched bursts with shifted csv window, take union
            hits = [(max(c0, s0), min(c1, s1)) for c0, c1 in candidates
                    if overlap(s0, s1, c0, c1) > 0]
            if not hits:
                print(f"  !! no pcap bursts matched {w['label']} — keeping csv window "
                      f"(offset {off_h:+d}h) unverified")
                p0, p1 = s0, s1
            else:
                p0 = min(h[0] for h in hits)
                p1 = max(h[1] for h in hits)
            n_pkts = sum(len(att_times.get(ip, [])) for ip in w["src_ips"])
            conf = "pcap-verified" if hits else "csv-only"
            new_windows.append({**w, "start": int(p0), "end": int(p1),
                                "verified": conf, "offset_applied_h": off_h})
            print(f"  [{conf}] {w['label']:<28} "
                  f"{datetime.fromtimestamp(p0):%m-%d %H:%M:%S} -> "
                  f"{datetime.fromtimestamp(p1):%H:%M:%S}  "
                  f"(csv dur {dur_csv//60}min, attacker pkts seen: {n_pkts})")

        result[pcap_name] = {
            "pcap": pcap_name,
            "pcap_start_epoch": int(t_start),
            "pcap_end_epoch": int(t_end),
            "benign_span": [int(t_start), int(t_end)],
            "windows": sorted(new_windows, key=lambda x: x["start"]),
        }

    Path(args.out).write_text(json.dumps(result, indent=2))
    print(f"\nwrote {args.out}")

    # human-readable table for docs/
    lines = ["# CICIDS2017 attack windows (pcap time base)\n",
             "Derived by `replay/derive_windows_from_pcap.py`: attacker-IP packet bursts ",
             f"located in the raw pcaps (burst gap > {GAP_S}s), matched to CSV labels.\n",
             "| Day | Label | Start (UTC) | End (UTC) | Verified | Flows(CSV) |",
             "|---|---|---|---|---|---|"]
    for pcap_name, e in result.items():
        for w in e["windows"]:
            lines.append(
                f"| {pcap_name.replace('-WorkingHours.pcap','').replace('workingHours.pcap','')} "
                f"| {w['label']} | {datetime.fromtimestamp(w['start']):%m-%d %H:%M:%S} "
                f"| {datetime.fromtimestamp(w['end']):%H:%M:%S} "
                f"| {w['verified']} | {w['n_flows']} |")
    Path("docs/ATTACK_WINDOWS.md").write_text("\n".join(lines) + "\n")
    print("wrote docs/ATTACK_WINDOWS.md")


if __name__ == "__main__":
    main()
