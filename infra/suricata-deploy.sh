#!/usr/bin/env bash
# Suricata deploy/bootstrap for Sentinel — Sandbox-First Mode (§9-I6).
#
# COMMIT-ONLY artifact: every environment change this script makes is
# reproducible from git; nothing lives only in a session.
#
#   - Installs Suricata via the distro package manager when absent.
#   - Writes a minimal eve.json-only config suitable for capturing on
#     loopback/dummy interfaces inside ONE container (I6), home-net set to
#     RFC1918 so no customer topology is hardcoded (P1).
#   - Does NOT start live capture by itself; operators/harness (M6) run:
#       suricata -c <conf> -i <iface>
#
# Usage: sudo ./suricata-deploy.sh [OUTPUT_DIR]
set -euo pipefail

OUT_DIR="${1:-/etc/sentinel}"
CONF="$OUT_DIR/suricata.yaml"
EVE_DIR="$OUT_DIR/eve"

if ! command -v suricata >/dev/null 2>&1; then
    if command -v apt-get >/dev/null 2>&1; then
        apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends suricata
    elif command -v dnf >/dev/null 2>&1; then
        dnf install -y suricata
    else
        echo "ERROR: no supported package manager found; install Suricata manually." >&2
        exit 1
    fi
fi

mkdir -p "$EVE_DIR"

cat > "$CONF" <<'YAML'
# Minimal Sentinel eve.json config — Sandbox-First (§9-I6). P1: no customer
# topology hardcoded; HOME_NET below is the RFC1948 placeholder set that a
# deployment overrides from its own declared world (config.yaml).
vars:
  address-groups:
    HOME_NET: "[10.0.0.0/8,172.16.0.0/12,192.168.0.0/16]"
    EXTERNAL_NET: "!$HOME_NET"
  port-groups:
    HTTP_PORTS: "80,8080"
    SSH_PORTS: "22"

default-log-dir: EVE_DIR_PLACEHOLDER

outputs:
  - fast: {enabled: no}
  - eve-log:
      enabled: yes
      filetype: regular            # streamed file; Sentinel tails it line-by-line
      filename: eve.json
      types:
        - alert
        - flow
        - dns: {enabled: yes}
        - tls: {extended: yes}

logging: {level: notice}
YAML

sed -i "s|EVE_DIR_PLACEHOLDER|$EVE_DIR|" "$CONF"

echo "suricata bootstrap complete:"
echo "  conf : $CONF"
echo "  eve  : $EVE_DIR/eve.json   (tail this with Sentinel's streaming parser)"
