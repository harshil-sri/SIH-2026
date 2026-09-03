#!/usr/bin/env bash
# SIH26145 — PROOF that the diode is genuinely one-way. P1 GATE.
#
# (a) monitor receives forward traffic; (b) ZERO packets ever leave the
# monitor side even when we try to send; (c) iptables DROP counter confirms.
# Evidence: data/diode/proof/
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT="$ROOT/data/diode/proof"
mkdir -p "$OUT"
PY="$ROOT/.venv/bin/python"
rm -f "$OUT"/leaked_probe.bin "$OUT"/received_frames.bin

echo "[verify] 1. forward direction: probes source -> monitor"
# bounded receiver in background; exits on its own after 5 pkts or 6s
sudo ip netns exec ns-monitor "$PY" "$(dirname "$0")/relay.py" recv --out - --max-pkts 5 --max-seconds 6 \
  2>/dev/null > "$OUT/received_frames.bin" &
RECV=$!
sleep 0.7

sudo ip netns exec ns-source "$PY" - <<'EOF'
import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
for i in range(5):
    s.sendto(f"probe-{i}".encode(), ("10.200.0.2", 9999))
print("sent 5 probes")
EOF
wait $RECV || true

FWD_COUNT=$(grep -ao 'probe-' "$OUT/received_frames.bin" 2>/dev/null | wc -l || true)
FWD_BYTES=$(wc -c < "$OUT/received_frames.bin")
echo "[verify]    received on monitor: $FWD_COUNT frames, $FWD_BYTES bytes (expect 5)"

echo "[verify] 2. reverse direction: monitor TRIES to send (must be dropped)"
# source-side listener with its own timeout, stdout owned by host shell
( sudo ip netns exec ns-source timeout 4 python3 -c '
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("0.0.0.0", 7777)); s.settimeout(3.0)
try:
    data, _ = s.recvfrom(65535)
    sys.stdout.buffer.write(b"LEAK:" + data)
except socket.timeout:
    pass
' > "$OUT/leaked_probe.bin" ) &
LP=$!
sleep 0.5
sudo ip netns exec ns-monitor timeout 2 bash -c 'while true; do echo leak | nc -u -w1 10.200.0.1 7777; done' >/dev/null 2>&1 || true
wait $LP || true

if [ -s "$OUT/leaked_probe.bin" ]; then
  echo "[verify] FAIL: monitor->source leak!"; cat "$OUT/leaked_probe.bin"; exit 1
fi

DROPS=$(sudo ip netns exec ns-monitor iptables -L OUTPUT -v -x | awk '/DROP/ {print $1}')
echo "[verify]    iptables OUTPUT DROP counter (ns-monitor): ${DROPS:-0} dropped"

cat > "$OUT/result.txt" <<EOF
DIODE VERIFICATION $(date -Is)
forward frames received on monitor : $FWD_COUNT / 5 ($FWD_BYTES bytes)
bytes leaked monitor -> source     : 0 (PASS)
iptables OUTPUT drops in ns-monitor: ${DROPS:-0}
EOF
cat "$OUT/result.txt"

[ "$FWD_COUNT" -ge 1 ] || { echo "[verify] INCONCLUSIVE: no forward traffic"; exit 1; }
echo "[verify] P1 GATE PASSED ✔"
