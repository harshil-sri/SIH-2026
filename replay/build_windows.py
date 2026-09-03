#!/usr/bin/env python3
"""SIH26145 — Derive authoritative attack time-windows from CICIDS2017 labels.

Reads GeneratedLabelledFlows CSVs (they include Timestamp + IPs), groups by
attack label per source day, and emits data/windows.json:

    { "<day-pcap-name>": {
        "pcap": "Monday-WorkingHours.pcap",
        "windows": [ {"label": "DoS Hulk", "start": epoch, "end": epoch,
                      "n_flows": 461908, "src_ips": [...]} , ... ],
        "benign_span": [epoch, epoch]
      }, ... }

Timestamp quirk handled: CICIDS2017 CSV dates are ambiguous d/m vs m/d; the
entire capture week is 3–7 JULY 2017, so we pick the reading whose month == 7.

Usage:
    python replay/build_windows.py [--glf-dir datasets/raw/glf] [--out data/windows.json]
"""
import argparse
import calendar
import json
import re
from datetime import datetime
from pathlib import Path

DAY_TO_PCAP = {
    "Monday": "Monday-WorkingHours.pcap",
    "Tuesday": "Tuesday-WorkingHours.pcap",
    "Wednesday": "Wednesday-workingHours.pcap",
    "Thursday": "Thursday-WorkingHours.pcap",
    "Friday": "Friday-WorkingHours.pcap",
}

TS_RE = re.compile(r"(\d{1,2})/(\d{1,2})/(\d{4})\s+(\d{1,2}):(\d{2})(?::(\d{2}))?")


def parse_ts(raw: str):
    """Return epoch seconds, resolving the d/m-vs-m/d ambiguity via month==7."""
    m = TS_RE.search(str(raw))
    if not m:
        return None
    a, b, y, hh, mm, ss = int(m[1]), int(m[2]), int(m[3]), int(m[4]), int(m[5]), int(m[6] or 0)
    # candidate readings; the true one is in July 2017 (capture week 3–7 July)
    for day, mon in ((a, b), (b, a)):
        if mon == 7 and day in range(1, 32):
            return calendar.timegm((y, mon, day, hh, mm, ss))
    return None


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--glf-dir", default="datasets/raw/glf")
    ap.add_argument("--out", default="data/windows.json")
    args = ap.parse_args()

    out: dict[str, dict] = {}
    for csv in sorted(Path(args.glf_dir).rglob("*Flows.csv")) or sorted(Path(args.glf_dir).rglob("*.csv")):
        name = csv.stem.replace(".pcap_ISCX", "")
        day_key = next((d for d in DAY_TO_PCAP if name.startswith(d)), None)
        if not day_key:
            continue

        import pandas as pd
        cols = pd.read_csv(csv, nrows=0).columns.tolist()
        ts_col = next(c for c in cols if c.strip().lower() == "timestamp")
        lbl_col = next(c for c in cols if c.strip().lower() == "label")
        sip_col = next((c for c in cols if c.strip() == "Source IP"), None)

        df = pd.read_csv(csv, usecols=[ts_col, lbl_col] + ([sip_col] if sip_col else []),
                         dtype=str, encoding="latin-1")
        df["ts"] = df[ts_col].map(parse_ts)
        df = df.dropna(subset=["ts"])
        df[lbl_col] = df[lbl_col].str.strip()
        df["sip"] = df[sip_col].str.strip() if sip_col else ""

        windows, benign_rows = [], df[df[lbl_col] == "BENIGN"]
        for label, g in df[df[lbl_col] != "BENIGN"].groupby(lbl_col):
            sips = sorted(g["sip"].unique())[:5]
            windows.append({
                "label": label,
                "start": int(g["ts"].min()),
                "end": int(g["ts"].max()),
                "n_flows": int(len(g)),
                "src_ips": sips,
            })
        entry = {
            "pcap": DAY_TO_PCAP[day_key],
            "csv_source": csv.name,
            "windows": sorted(windows, key=lambda w: w["start"]),
            "benign_span": [int(benign_rows["ts"].min()), int(benign_rows["ts"].max())]
            if len(benign_rows) else None,
            "n_flows_total": int(len(df)),
        }
        out[entry["pcap"]] = entry

    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    Path(args.out).write_text(json.dumps(out, indent=2))

    print(f"wrote {args.out} ({len(out)} days)")
    for pcap, e in out.items():
        print(f"\n{pcap}  ({e['n_flows_total']} labeled flows)")
        for w in e["windows"]:
            s, t = datetime.utcfromtimestamp(w["start"]), datetime.utcfromtimestamp(w["end"])
            print(f"   {s:%m-%d %H:%M:%S} -> {t:%H:%M:%S}  {w['label']:<28} {w['n_flows']:>9} flows")


if __name__ == "__main__":
    main()
