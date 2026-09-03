#!/usr/bin/env python3
"""SIH26145 — execute the replay plan end-to-end.

Reads data/plan.json, ensures the diode is up, replays every slice through it
at 1x timing, captures monitor-side traffic, and writes the capture manifest:

    data/captures/manifest.jsonl  (one row per slice:
        slice_id, label(s), source day/window, expected/captured packet counts)

Usage:  python replay/run_plan.py [--plan data/plan.json] [--out-dir data/captures]
                                    [--only LABEL] [--multiplier 1.0]
"""
import argparse
import json
import subprocess
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def diode_up() -> bool:
    r = subprocess.run(["sudo", "ip", "netns", "list"], capture_output=True, text=True)
    return "ns-source" in r.stdout and "ns-monitor" in r.stdout


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--plan", default="data/plan.json")
    ap.add_argument("--out-dir", default="data/captures")
    ap.add_argument("--only", default=None, help="substring filter on label or slice_id")
    ap.add_argument("--multiplier", type=float, default=1.0)
    args = ap.parse_args()

    plan = json.loads(Path(args.plan).read_text())
    out_dir = ROOT / args.out_dir
    out_dir.mkdir(parents=True, exist_ok=True)
    manifest_path = out_dir / "manifest.jsonl"

    done_ids = set()
    if manifest_path.exists():
        done_ids = {json.loads(l)["slice_id"] for l in manifest_path.read_text().splitlines() if l.strip()}

    if not diode_up():
        print("[plan] diode not up -> running diode/setup_diode.sh")
        subprocess.run(["bash", str(ROOT / "diode/setup_diode.sh")], check=True)

    t_all = time.time()
    for i, m in enumerate(plan):
        if m["label"] == "BENIGN" and False:   # keep for debugging filters
            pass
        if args.only and args.only.lower() not in (m["label"] + m["slice_id"]).lower():
            continue
        if m["slice_id"] in done_ids:
            print(f"[{i+1}/{len(plan)}] {m['slice_id']} already captured, skip")
            continue
        cap_path = out_dir / f"{m['slice_id']}.pcap"
        print(f"\n[{i+1}/{len(plan)}] {m['label']} ({m.get('duration_s',0)}s planned)")
        t0 = time.time()
        subprocess.run(["bash", str(ROOT / "replay/replay_slice.sh"),
                        m["slice_path"], str(cap_path), str(args.multiplier)], check=True)
        got = int(subprocess.run(["capinfos", "-c", str(cap_path)],
                                 capture_output=True, text=True).stdout
                  .split("Number of packets")[-1].split("=")[-1].split()[0])
        row = {**{k: m[k] for k in ("slice_id", "day", "label", "n_packets")},
               "captured_packets": got,
               "replay_wall_s": round(time.time() - t0, 1),
               "capture": str(cap_path.relative_to(ROOT))}
        with manifest_path.open("a") as f:
            f.write(json.dumps(row) + "\n")

    total = sum(r["replay_wall_s"] for r in map(json.loads, manifest_path.read_text().splitlines()))
    print(f"\nDONE: {len(done_ids)+len(plan) and 'see'} {manifest_path} "
          f"(total replay wall-time {total/60:.1f} min)")


if __name__ == "__main__":
    main()
