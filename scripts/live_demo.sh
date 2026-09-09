#!/usr/bin/env bash
# SIH26145 — LIVE DEMO orchestrator.
#
# Brings up the diode, starts monitor-side scoring pipeline + relay + a
# scripted benign/attack schedule through the transport-layer one-way relay,
# while the FastAPI service and dashboard render results live.
#
# Usage:  bash scripts/live_demo.sh            # full demo loop
#         bash scripts/live_demo.sh --once     # single pass (CI-friendly)
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PY="$ROOT/.venv/bin/python"
ONCE=0
[ "${1:-}" = "--once" ] && ONCE=1

echo "── [1/5] diode up"
bash "$ROOT/diode/setup_diode.sh" >/dev/null

echo "── [2/5] inference service"
curl -sf http://127.0.0.1:8200/health >/dev/null || {
  ( cd "$ROOT" && "$PY" -m uvicorn serving.app:app --port 8200 > data/api.log 2>&1 & )
  for i in $(seq 1 30); do curl -sf http://127.0.0.1:8200/health >/dev/null && break; sleep 1; done
}
curl -s http://127.0.0.1:8200/health | tee "$ROOT/data/demo_health.json"

echo "── [2.5/5] host tcp proxy for api"
"$PY" "$ROOT/scripts/tcp_proxy.py" 10.200.1.1 8200 127.0.0.1 8200 > /dev/null 2>&1 &
PROXY=$!
sleep 1

echo "── [3/5] monitor-side pipeline (recvfrom-only)"
sudo ip netns exec ns-monitor \
  timeout 300 "$PY" "$ROOT/serving/live_pipeline.py" --window-s 3 --api http://10.200.1.1:8200 &
LIVE=$!
sleep 1

echo "── [4/5] relay sender inside source ns"
sudo ip netns exec ns-source "$PY" "$ROOT/diode/relay.py" send --in-port 10500 \
  > /dev/null 2>&1 &
RELAY=$!
sleep 1

echo "── [5/5] traffic schedule (benign → attacks → benign)"
run() { sudo ip netns exec ns-source "$PY" "$ROOT/attacks/generate.py" "$@"; }
schedule() {
  run benign --seconds 15
  echo ">>> INJECTING udp_flood"
  run udp_flood --rate-pps 2500 --seconds 6
  run benign --seconds 10
  echo ">>> INJECTING covert_timing channel"
  run covert_timing --seconds 18
  run benign --seconds 10
  echo ">>> INJECTING stego_payload exfil"
  run stego_payload --seconds 16
  [ "$ONCE" = 1 ] || {
    echo ">>> INJECTING malformed frames"
    run malformed --count 40
    run benign --seconds 8
  }
}
schedule
[ "$ONCE" = 1 ] || schedule

sleep 4   # let last buckets flush
kill $LIVE $RELAY $PROXY 2>/dev/null || true
echo "demo pass complete — see dashboard at http://localhost:8400"
