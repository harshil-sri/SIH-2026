#!/usr/bin/env bash
# SIH26145 — replay ONE slice through the emulated diode, capture on monitor side.
#
# Usage: bash replay/replay_slice.sh <slice.pcap> <capture-out.pcap> [multiplier]
#
# - capture side uses tcpdump -c <expected-pkts> so it EXITS ITSELF when the
#   slice is fully received (no root-process killing needed); wall-clock timeout
#   as safety net.
# - tcpreplay --multiplier=1.0 preserves original inter-packet timing (IAT
#   features are timing-sensitive; do not speed up training-data replays).
set -euo pipefail
SLICE="$1"; OUT="$2"; MULT="${3:-1.0}"

N_PKTS=$(capinfos -c "$SLICE" 2>/dev/null | awk '
  /Number of packets/ {
    raw=$0; sub(/.*:/,"",raw); gsub(/ /,"",raw); mult=1
    if (raw ~ /k|K/) { mult=1000; gsub(/[kK]/,"",raw) }
    if (raw ~ /[Mm]/) { mult=1000000; gsub(/[Mm]/,"",raw) }
    printf "%.0f\n", raw*mult
  }')
DUR=$(capinfos -u "$SLICE" 2>/dev/null | sed -nE 's/.*[Cc]apture duration[^0-9]*([0-9]+\.?[0-9]*).*/\1/p')
WALL=$(python3 -c "print(int(${DUR:-60}/$MULT)+120)")

mkdir -p "$(dirname "$OUT")" replay/logs
LOG="replay/logs/$(basename "${OUT%.pcap}").replay.log"

echo "[replay] $(basename "$SLICE"): $N_PKTS pkts / ${DUR:-?}s at ${MULT}x -> $OUT"
( sudo ip netns exec ns-monitor timeout "$WALL" tcpdump -i veth-mon -U -nn -c "$N_PKTS" -w - \
    2> "$LOG.cap" | cat > "$OUT" ) &
CAP=$!
sleep 0.5
sudo ip netns exec ns-source timeout "$WALL" tcpreplay -i veth-src --multiplier="$MULT" \
  --stats=30 "$SLICE" > "$LOG" 2>&1 || true

# wait for capture to self-terminate (-c) or the wrapper to end
wait $CAP || true

GOT=$(capinfos -c "$OUT" 2>/dev/null | awk '
  /Number of packets/ {
    raw=$0; sub(/.*:/,"",raw); gsub(/ /,"",raw); mult=1
    if (raw ~ /k|K/) { mult=1000; gsub(/[kK]/,"",raw) }
    if (raw ~ /[Mm]/) { mult=1000000; gsub(/[Mm]/,"",raw) }
    printf "%.0f", raw*mult
  }')
echo "[replay] captured $GOT / $N_PKTS packets -> $OUT"
[ "${GOT:-0}" -ge 1 ] || { echo "[replay] FAIL: empty capture"; exit 1; }
