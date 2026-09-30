#!/usr/bin/env bash
# SIH26145 — LIVE DEMO orchestrator (tap-authoritative).
#
# Brings up the one-way diode, starts the monitor-side detector pipeline WITH the
# L3 tap on veth-mon (full frames: ports/TTL/payload sizes the models were
# trained on), and replays a scripted benign -> attack -> benign schedule whose
# generator-produced threats are SHAPES the detectors are honest about:
#    udp_flood --spoof  -> source-entropy (VOLUMETRIC)
#    portscan           -> port-fan-out/cover (SCAN_RECON)
#    beacon             -> metronome inter-arrival cadence (BEACON)
#    malformed          -> parser resilience under malformed frames
# The relay still carries the payloads across the diode; the tap additionally
# sees the raw frames, so spoofed-source floods and scans (invisible to a relay
# that collapses to one transport source) become observable.
#
# Usage:  bash scripts/live_demo.sh           # schedule twice (failsafe replay)
#         bash scripts/live_demo.sh --once    # single pass (CI-friendly)
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PY="$ROOT/.venv/bin/python"
ONCE=0
[ "${1:-}" = "--once" ] && ONCE=1

echo "── [1/6] diode up"
bash "$ROOT/diode/setup_diode.sh" >/dev/null

echo "── [2/6] inference service + console (scripts/serve.sh start prod)"
# Force the production build on :8401 rather than auto: auto silently falls
# back to the Vite dev server when the node build isn't detected, and dev then
# lands on a random port if :8080 is taken (an unrelated local process holds it)
# — so the console goes missing from the :8401 the demo script points at. Prod
# fails loudly if the build is absent, which is the correct signal to run
# `make frontend-build` first.
bash "$ROOT/scripts/serve.sh" start prod

echo "── [3/6] host tcp proxy (ns-monitor management veth -> host API)"
"$PY" "$ROOT/scripts/tcp_proxy.py" 10.200.1.1 8200 127.0.0.1 8200 \
  > "$ROOT/data/demo_proxy.log" 2>&1 &
PROXY=$!
sleep 1

echo "── [4/6] monitor-side pipeline (tap-authoritative, 3s buckets)"
echo "        log -> data/demo_pipeline.log  (alerts marked ⚠)"
sudo ip netns exec ns-monitor env PYTHONUNBUFFERED=1 \
  timeout 600 "$PY" "$ROOT/serving/live_pipeline.py" --window-s 3 --tap-dev veth-mon \
  --api http://10.200.1.1:8200 > "$ROOT/data/demo_pipeline.log" 2>&1 &
LIVE=$!
sleep 2

echo "── [5/6] relay sender inside source netns"
sudo ip netns exec ns-source "$PY" "$ROOT/diode/relay.py" send --in-port 10500 \
  > /dev/null 2>&1 &
RELAY=$!
sleep 1

echo "── [6/6] traffic schedule (benign → detector shapes → benign)"
run() { sudo ip netns exec ns-source "$PY" "$ROOT/attacks/generate.py" "$@"; }
schedule() {
  run benign --seconds 12
  echo ">>> INJECTING spoofed-source flood (volumetric)"
  run udp_flood --spoof --seconds 8
  run benign --seconds 8
  echo ">>> INJECTING port-scan recon (scan_recon)"
  run portscan --seconds 8
  run benign --seconds 8
  echo ">>> INJECTING C2 beacon cadence (beacon)"
  run beacon --seconds 16
  # benign after the beacon must run long enough that the 10.200.0.42 bucket
  # goes stale AND flushes while the beacon detector's 6-minute evidence buffer
  # is still warm — otherwise the flush looks at an empty window row set and
  # the very strand we demo is the one that clips (measured: 4 bad-coin flips
  # in a 5-run series). 12s guarantees the stale-flush lands inside the window.
  run benign --seconds 12
  echo ">>> INJECTING malformed frames (parser resilience)"
  run malformed --count 40
  run benign --seconds 8
}
schedule
[ "$ONCE" = 1 ] || schedule

sleep 5   # let the last buckets flush + score

ALERTS="$(grep -cE "⚠" "$ROOT/data/demo_pipeline.log" || :)"
echo ""
echo "demo $([ "$ONCE" = 1 ] && echo "(once)" || echo "double") pass complete — lit $ALERTS alert window(s)"
echo "  pipeline log        data/demo_pipeline.log"
echo "  inline console      http://127.0.0.1:8401"
grep -E "⚠" "$ROOT/data/demo_pipeline.log" | tail -8

echo "── teardown"
kill "$LIVE" "$PROXY" "$RELAY" 2>/dev/null || true
# the sudo-wrapped root children outlive their wrapper on some systems; sweep
sudo ip netns exec ns-monitor pkill -f live_pipeline.py 2>/dev/null || true
sudo ip netns exec ns-source pkill -f "relay.py send" 2>/dev/null || true
true