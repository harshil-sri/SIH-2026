#!/usr/bin/env bash
# SIH26145 — remove all diode state (namespaces, veth, rules).
sudo ip netns del ns-source 2>/dev/null || true
sudo ip netns del ns-monitor 2>/dev/null || true
exit 0
