#!/usr/bin/env bash
# Zeek deploy/bootstrap for Sentinel — Sandbox-First Mode (§9-I6).
#
# COMMIT-ONLY artifact: reproducible from git, nothing session-local.
#
#   - Installs Zeek via package manager when absent.
#   - Writes a minimal site policy enabling the four logs Sentinel ingests
#     in M1: conn, dns, ssl, notice. Logs land under LOGDIR.
#   - Does NOT start live capture; operators/harness (M6) run:
#       zeek -C -r <pcap> local        (replay)      or
#       zeekctl deploy                  (live, per deployment)
#
# Usage: sudo ./zeek-deploy.sh [OUTPUT_DIR]
set -euo pipefail

OUT_DIR="${1:-/etc/sentinel}"
SITE_DIR="$OUT_DIR/zeek-site"
LOGDIR="$OUT_DIR/zeek-logs"

if ! command -v zeek >/dev/null 2>&1 && ! command -v bro >/dev/null 2>&1; then
    if command -v apt-get >/dev/null 2>&1; then
        apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends zeek
    elif command -v dnf >/dev/null 2>&1; then
        dnf install -y zeek
    else
        echo "ERROR: no supported package manager found; install Zeek manually." >&2
        exit 1
    fi
fi

mkdir -p "$SITE_DIR" "$LOGDIR"

cat > "$SITE_DIR/local.zeek" <<'ZEEK'
# Minimal Sentinel site policy — M1 log set only (conn/dns/ssl/notice).
@load base/frameworks/notice
@load policy/protocols/conn
@load policy/protocols/dns
@load policy/protocols/ssl

redef Log::default_logdir = "LOGDIR_PLACEHOLDER";
ZEEK

sed -i "s|LOGDIR_PLACEHOLDER|$LOGDIR|" "$SITE_DIR/local.zeek"

echo "zeek bootstrap complete:"
echo "  site : $SITE_DIR/local.zeek"
echo "  logs : $LOGDIR   (conn.log dns.log ssl.log notice.log -> streaming reader)"
