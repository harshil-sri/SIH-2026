#!/usr/bin/env python3
"""SIH26145 — Cut replay slices from the day pcaps according to attack windows."""
import argparse
import json
import subprocess
from datetime import datetime
from pathlib import Path

MAX_ATTACK_MIN = 4.0
CTX_PRE_MIN = 1.0
CTX_POST_MIN = 1.0
BENIGN_SLICE_MIN = 5.0
BENIGN_PER_DAY = 4


def capinfos_get(pcap: Path, flags: str) -> str:
    """Run capinfos, capture both stdout+stderr (this version outputs to stderr)."""
    r = subprocess.run(["capinfos"] + flags.split() + [str(pcap)],
                       capture_output=True, text=True)
    return r.stdout + r.stderr


def pcap_start_epoch(pcap: Path) -> float:
    txt = capinfos_get(pcap, "-a")
    for line in txt.splitlines():
        if line.strip().lower().startswith("first packet time"):
            raw = line.split(":", 1)[-1].strip()
            for fmt in ("%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%d %H:%M:%S"):
                try:
                    return datetime.strptime(raw, fmt).timestamp()
                except ValueError:
                    continue
    raise RuntimeError(f"capinfos gave no parseable start time for {pcap}")


def capinfos_val(pcap: Path, flags: str, key: str) -> float | int:
    txt = capinfos_get(pcap, flags)
    for line in txt.splitlines():
        if key.lower() in line.lower():
            parts = line.replace(":", "=").split("=")
            if len(parts) > 1:
                raw = parts[-1].strip().rstrip("s").replace(",", "").replace(" ", "")
                try:
                    return float(raw)
                except ValueError:
                    continue
    return 0


def slug(s: str) -> str:
    return "".join(c if c.isalnum() else "-" for c in s.lower()).strip("-")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--pcap-dir", default="datasets/raw")
    ap.add_argument("--windows", default="data/windows_pcap.json")
    ap.add_argument("--out-dir", default="replay/slices")
    ap.add_argument("--plan-out", default="data/plan.json")
    args = ap.parse_args()

    windows_db = json.loads(Path(args.windows).read_text())
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    plan = []
    for pcap_name, entry in sorted(windows_db.items()):
        pcap = Path(args.pcap_dir) / pcap_name
        if not pcap.exists():
            continue
        t0 = pcap_start_epoch(pcap)
        benign_span = entry.get("benign_span")

        if benign_span and "Monday" in pcap_name:
            b0, b1 = benign_span
            span = max(1.0, b1 - b0)
            for i in range(BENIGN_PER_DAY):
                s = b0 + span * (i + 0.5) / BENIGN_PER_DAY - BENIGN_SLICE_MIN * 30
                e = s + BENIGN_SLICE_MIN * 60
                plan.append({"day": pcap_name, "label": "BENIGN", "t_start": int(s),
                             "t_end": int(e), "src_pcap": str(pcap)})
        for w in entry["windows"]:
            s = w["start"] - CTX_PRE_MIN * 60
            e = min(w["end"], w["start"] + MAX_ATTACK_MIN * 60) + CTX_POST_MIN * 60
            plan.append({"day": pcap_name, "label": w["label"], "t_start": int(s),
                         "t_end": int(e), "src_pcap": str(pcap)})

    by_day: dict[str, list] = {}
    for p in plan:
        by_day.setdefault(p["day"], []).append(p)
    final = []
    for day, items in by_day.items():
        items.sort(key=lambda x: x["t_start"])
        last_end = -1
        for it in items:
            it["t_start"] = max(it["t_start"], last_end + 1)
            if it["t_start"] >= it["t_end"]:
                continue
            last_end = it["t_end"]
            final.append(it)

    manifest = []
    for i, p in enumerate(final):
        sid = f"{Path(p['day']).stem.split('-')[0].lower()}__{slug(p['label'])}__{i}"
        dst = out_dir / f"{sid}.pcap"
        a = datetime.utcfromtimestamp(p["t_start"]).strftime("%Y-%m-%d %H:%M:%S")
        b = datetime.utcfromtimestamp(p["t_end"]).strftime("%Y-%m-%d %H:%M:%S")
        if not dst.exists():
            subprocess.run(["editcap", "-A", a, "-B", b, p["src_pcap"], str(dst)], check=True)
        n_pkts = int(capinfos_val(dst, "-c", "Number of packets"))
        dur_s = float(capinfos_val(dst, "-u", "Capture duration"))
        manifest.append({**p, "slice_id": sid, "slice_path": str(dst), "n_packets": n_pkts,
                         "duration_s": round(dur_s, 1)})
        print(f"  {sid:<42} {n_pkts:>8} pkts  {dur_s:>7.1f}s  [{p['label']}]")

    Path(args.plan_out).write_text(json.dumps(manifest, indent=2))
    tot_s = sum(m["duration_s"] for m in manifest)
    print(f"\nplan: {len(manifest)} slices, {tot_s/60:.1f} min total replay @1x -> {args.plan_out}")


if __name__ == "__main__":
    main()