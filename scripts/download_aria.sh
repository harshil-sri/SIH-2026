#!/usr/bin/env bash
# SIH26145 — aria2c parallel downloader: 5 pcaps x 8 segments each = 40 connections.
set -u
RAW="$(cd "$(dirname "${BASH_SOURCE[0]}")/../datasets/raw" && pwd)"
cd "$RAW"
HF="https://huggingface.co/datasets/bencorn/CICIDS2017/resolve/main"
LOG="$RAW/download.log"

echo "=== parallel start $(date -Is) ===" >> "$LOG"

dl() {
  aria2c -c -x8 -s8 -k4M --retry-wait=3 --max-tries=0 --timeout=30 \
    --connect-timeout=15 --console-log-level=warn --summary-interval=120 \
    -o "$1" "$2" 2>&1 | tee -a "$LOG" | tail -1
}

for f in Monday-WorkingHours Tuesday-WorkingHours Wednesday-workingHours Thursday-WorkingHours Friday-WorkingHours; do
  dl "$f.pcap" "$HF/pcaps/$f.pcap" &
done

wait
echo "=== ARIA_ALL_DONE $(date -Is) ===" >> "$LOG"
