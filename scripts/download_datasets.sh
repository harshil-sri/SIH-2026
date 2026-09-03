#!/usr/bin/env bash
# SIH26145 — Tier-1 dataset downloader.
#
# Source: official UNB links (205.174.165.80 / cicresearch.ca) are gated behind a
# browser form as of 2026-08, so we pull from the HuggingFace mirror
# bencorn/CICIDS2017 (byte-identical files; CIC's license explicitly permits
# mirroring — cite Sharafaldin et al., ICISSP 2018 either way).
# CIDDS-001 comes straight from hs-coburg.de.
#
# Resumable (wget -c): safe to kill and re-run. No sudo required.
set -u
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RAW="$ROOT/datasets/raw"
mkdir -p "$RAW"
LOG="$RAW/download.log"
HF="https://huggingface.co/datasets/bencorn/CICIDS2017/resolve/main"

PCAPS=(
  Monday-WorkingHours.pcap        # pure benign -> LSTM-AE training data (~10.3GB)
  Tuesday-WorkingHours.pcap       # FTP-Patator, SSH-Patator (~10.5GB)
  Wednesday-workingHours.pcap     # DoS slowloris/slowhttptest/hulk/goldeneye, Heartbleed (~12.8GB)
  Thursday-WorkingHours.pcap      # Web attacks (x2), Infiltration (~7.9GB)
  Friday-WorkingHours.pcap        # Bot, PortScan, DDoS LOIT (~8.4GB)
)

echo "=== download started $(date -Is) ===" >> "$LOG"
cd "$RAW"

wget -nc -q "$HF/csvs/MachineLearningCSV.zip" &
wget -nc -q https://www.hs-coburg.de/wp-content/uploads/2024/11/CIDDS-001.zip &

for f in "${PCAPS[@]}"; do
  wget -c -q "$HF/pcaps/$f" &
done

wait
echo "=== ALL_DOWNLOADS_DONE $(date -Is) ===" >> "$LOG"

# integrity gate: every pcap must be a real capture file, not an HTML error page
echo "=== file-type check ===" >> "$LOG"
for f in "${PCAPS[@]}"; do
  if file "$f" | grep -qi 'pcap'; then echo "OK   $f" >> "$LOG"; else echo "BAD  $f -> $(file -b "$f")" >> "$LOG"; fi
done
