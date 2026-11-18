#!/usr/bin/env bash
# Lock the Sentinel host down: SSH + HTTPS only, and only from the networks
# you name. Everything else inbound is dropped.
#
#   sudo ALLOW_CIDRS="172.27.27.0/24 10.212.134.0/24" ./infra/firewall.sh
#
# ALLOW_CIDRS = your internal LAN + the FortiGate SSL-VPN address pool.
set -euo pipefail

if [[ $EUID -ne 0 ]]; then echo "run with sudo" >&2; exit 1; fi
if [[ -z "${ALLOW_CIDRS:-}" ]]; then
  echo "set ALLOW_CIDRS, e.g. ALLOW_CIDRS=\"172.27.27.0/24 10.212.134.0/24\"" >&2
  exit 1
fi
command -v ufw >/dev/null || apt-get install -y ufw

# Rules first, enable last: never cut the SSH session we are running in.
ufw default deny incoming
ufw default allow outgoing
for cidr in $ALLOW_CIDRS; do
  ufw allow from "$cidr" to any port 22 proto tcp comment "sentinel ssh"
  ufw allow from "$cidr" to any port 443 proto tcp comment "sentinel ui"
  ufw allow from "$cidr" to any port 80 proto tcp comment "sentinel ui redirect"
done
ufw --force enable
ufw status verbose
