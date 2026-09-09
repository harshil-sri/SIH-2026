#!/usr/bin/env bash
# SIH26145 — Diode emulation, POLICY LAYER.
#
# Creates two network namespaces joined by a veth pair. The monitor namespace
# has an iptables OUTPUT DROP rule: it can RECEIVE but never SEND. This is the
# policy-layer guarantee of unidirectionality (the transport-layer guarantee is
# the relay in diode/relay.py, which structurally has no send path).
#
# NOTE: runs unprivileged; every privileged call goes through the scoped
# NOPASSWD sudoers rule (scripts/bootstrap_sudo.sh), e.g. `sudo ip netns exec`.
#
# Usage:   bash diode/setup_diode.sh
# Verify:  bash diode/verify_diode.sh
set -euo pipefail

NS_SRC=ns-source
NS_MON=ns-monitor

echo "[diode] cleaning any previous state..."
bash "$(dirname "$0")/teardown_diode.sh" >/dev/null 2>&1 || true

echo "[diode] creating namespaces $NS_SRC / $NS_MON"
sudo ip netns add "$NS_SRC"
sudo ip netns add "$NS_MON"

echo "[diode] creating veth pair + moving ends into namespaces"
sudo ip link add veth-src type veth peer name veth-mon
sudo ip link set veth-src netns "$NS_SRC"
sudo ip link set veth-mon netns "$NS_MON"

echo "[diode] addressing + links up"
sudo ip netns exec "$NS_SRC" ip addr add 10.200.0.1/24 dev veth-src
sudo ip netns exec "$NS_MON" ip addr add 10.200.0.2/24 dev veth-mon
sudo ip netns exec "$NS_SRC" ip link set veth-src mtu 9000
sudo ip netns exec "$NS_MON" ip link set veth-mon mtu 9000
sudo ip netns exec "$NS_SRC" ip link set veth-src up
sudo ip netns exec "$NS_MON" ip link set veth-mon up
sudo ip netns exec "$NS_SRC" ip link set lo up
sudo ip netns exec "$NS_MON" ip link set lo up

echo "[diode] POLICY LAYER: dropping ALL outbound traffic on veth-mon in $NS_MON"
sudo ip netns exec "$NS_MON" iptables -A OUTPUT -o veth-mon -j DROP

# disable segment offload inside the namespaces: otherwise the kernel can
# coalesce packets (GSO/GRO), producing fake >MTU packets in captures that
# would distort our packet-size features.
sudo ip netns exec "$NS_SRC" ethtool -K veth-src tso off gso off gro off 2>/dev/null || true
sudo ip netns exec "$NS_MON" ethtool -K veth-mon tso off gso off gro off 2>/dev/null || true

echo "[diode] creating management veth pair for API access"
sudo ip link add veth-mgt type veth peer name veth-host
sudo ip link set veth-mgt netns "$NS_MON"
sudo ip addr add 10.200.1.1/24 dev veth-host
sudo ip link set veth-host up
sudo ip netns exec "$NS_MON" ip addr add 10.200.1.2/24 dev veth-mgt
sudo ip netns exec "$NS_MON" ip link set veth-mgt up

echo "[diode] done:"
echo "    ns-source(10.200.0.1 @ veth-src) ==> one-way ==> (veth-mon @ 10.200.0.2) ns-monitor"
echo "    ns-monitor(10.200.1.2 @ veth-mgt) <--> (veth-host @ 10.200.1.1) host proxy"
