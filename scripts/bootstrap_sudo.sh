#!/usr/bin/env bash
# SIH26145 — ONE-TIME privileged bootstrap. Human runs this ONCE with sudo:
#
#   sudo bash scripts/bootstrap_sudo.sh
#
# What it does:
#   1. Installs packet/network tooling needed by the diode + replay pipeline
#   2. Installs a SCOPED passwordless-sudo rule so the build agent can run
#      exactly these commands unattended (netns, iptables, capture/replay tools).
#      Nothing else is granted. Delete /etc/sudoers.d/sih26145 after the hackathon.
set -euo pipefail

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y --no-install-recommends \
  tcpdump tcpreplay tshark iptables libpcap-dev ethtool \
  python3-venv python3-pip python3-dev build-essential aria2

USER_NAME="${SUDO_USER:?run this with sudo as yourself}"
SUDOERS="/etc/sudoers.d/sih26145"
cat > "$SUDOERS" <<EOF
# SIH26145 scoped build permissions — remove this file post-hackathon
${USER_NAME} ALL=(root) NOPASSWD: /usr/sbin/ip, /usr/sbin/iptables, /usr/sbin/nft, /usr/bin/tcpreplay, /usr/bin/tcpdump, /usr/bin/tshark, /usr/bin/editcap, /usr/bin/capinfos, /usr/bin/mergecap, /usr/sbin/sysctl
EOF
chmod 440 "$SUDOERS"
visudo -c

echo ""
echo "Bootstrap complete. Tooling installed, scoped sudoers rule active for '${USER_NAME}'."
