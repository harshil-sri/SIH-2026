#!/usr/bin/env python3
"""SIH26145 — run the forward-only extractor over every captured slice.

Reads data/captures/manifest.jsonl, writes data/features/{flows_,srcwin_,seqs_}*.parquet|npz
plus extract_*.json info files. Skips slices already extracted.

Usage: python extraction/batch_extract.py [--captures-dir data/captures]
"""
import argparse
import json
import subprocess
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--captures-dir", default="data/captures")
    args = ap.parse_args()

    manifest = ROOT / args.captures_dir / "manifest.jsonl"
    rows = [json.loads(l) for l in manifest.read_text().splitlines() if l.strip()]
    print(f"{len(rows)} captured slices")

    t_all = time.time()
    for i, r in enumerate(rows):
        pcap = ROOT / r["capture"]
        out = subprocess.run(
            [sys.executable, str(ROOT / "extraction/extract_features.py"), str(pcap),
             "--label", r["label"], "--slice-id", r["slice_id"],
             "--out-dir", str(ROOT / "data/features")],
            capture_output=True, text=True)
        ok = out.returncode == 0
        marker = "✔" if ok else "✘"
        print(f"[{i+1}/{len(rows)}] {marker} {r['slice_id']} [{r['label']}]")
        if not ok:
            print(out.stderr[-800:])
    print(f"done in {(time.time()-t_all)/60:.1f} min -> data/features/")


if __name__ == "__main__":
    main()
