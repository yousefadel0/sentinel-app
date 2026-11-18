#!/usr/bin/env bash
# Sentinel — one-shot installer for a new site (Ubuntu Server 24.04 LTS).
#
#   sudo git clone https://github.com/<org>/sentinel-app /opt/sentinel-app
#   cd /opt/sentinel-app && sudo ./infra/install.sh
#
# Asks a few questions, then: installs Docker, writes .env + config.site.yaml,
# builds, runs the self-test, installs systemd units (service, daily rule
# update, daily backup, SPAN promiscuous mode), starts everything, downloads
# Suricata rules, optionally locks the firewall, and creates the first admin.
# Safe to re-run: existing .env / config.site.yaml are kept unless you agree.
# Enforcement stays OFF (dry-run, autonomy 0) — this installs an observer.
set -euo pipefail

APP_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$APP_DIR"
say()  { printf '\n\033[1;36m==> %s\033[0m\n' "$*"; }
warn() { printf '\033[1;33m[!] %s\033[0m\n' "$*"; }
ask()  { local q="$1" def="${2:-}" ans; read -r -p "$q${def:+ [$def]}: " ans; echo "${ans:-$def}"; }

[[ $EUID -eq 0 ]] || { echo "run with sudo" >&2; exit 1; }
if ! grep -q 'VERSION_ID="24.04"' /etc/os-release 2>/dev/null; then
  warn "tested on Ubuntu 24.04 LTS; continuing anyway"
fi

say "1/9 Packages (Docker, compose, buildx, git, openssl)"
apt-get update -qq
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq docker.io docker-compose-v2 \
  docker-buildx git openssl tcpdump >/dev/null
systemctl enable --now docker >/dev/null

say "2/9 Site questions"
ip -br addr | grep -v '^lo ' || true
MGMT_IP="$(ip route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src"){print $(i+1); exit}}')"
GW="$(ip route | awk '/default/{print $3; exit}')"
MGMT_IF="$(ip route | awk '/default/{print $5; exit}')"
echo "management address: ${MGMT_IP:-?} on ${MGMT_IF:-?}, gateway ${GW:-?}"
CAPTURE_IFACE="$(ask 'Capture (SPAN) interface — use the management one only for a single-NIC trial' "$MGMT_IF")"
SITE_NAME="$(ask 'Site name' "$(hostname -s)")"
CRITICAL="$(ask 'Critical servers as ip:name,ip:name (blank = none yet)' '')"
PROTECTED="$(ask 'Addresses that must NEVER be blocked (comma list)' "${MGMT_IP},${GW}")"
SITE_ADDR="$(ask 'Address operators will type in the browser' "$MGMT_IP")"
LAN_CIDR="$(ip -o -f inet addr show "$MGMT_IF" | awk '{print $4; exit}')"
ALLOW_CIDRS="$(ask 'Networks allowed to reach SSH+UI (LAN + VPN pool, space separated)' "$LAN_CIDR")"
ADMIN_USER="$(ask 'First admin username' 'admin')"

say "3/9 .env and config.site.yaml"
if [[ -f .env ]] && [[ "$(ask '.env exists — keep it? (y/n)' y)" == y ]]; then
  echo "keeping .env"
else
  cat > .env <<EOF
CAPTURE_IFACE=${CAPTURE_IFACE}
SENTINEL_CONFIG_FILE=./config.site.yaml
COMPOSE_PROFILES=capture,web
SENTINEL_SITE=${SITE_ADDR}
SENTINEL_OPS_UI_TOKEN=$(openssl rand -hex 24)
SENTINEL_LLM_API=
NVD_API_KEY=
SENTINEL_SOAR_TOKEN=
EOF
fi
chmod 600 .env

yaml_list() { local out="" x; IFS=',' read -ra xs <<< "$1"
  for x in "${xs[@]}"; do x="${x// /}"; [[ -n $x ]] && out+="${out:+, }${x}"; done; echo "[$out]"; }
crit_yaml="[]"
if [[ -n "$CRITICAL" ]]; then
  crit_yaml=""
  IFS=',' read -ra items <<< "$CRITICAL"
  for it in "${items[@]}"; do it="${it// /}"; [[ -z $it ]] && continue
    crit_yaml+=$'\n'"    - {ip: ${it%%:*}, hostname: ${it#*:}}"; done
fi
if [[ -f config.site.yaml ]] && [[ "$(ask 'config.site.yaml exists — keep it? (y/n)' y)" == y ]]; then
  echo "keeping config.site.yaml"
else
  cat > config.site.yaml <<EOF
site:
  name: ${SITE_NAME}
  critical_assets: ${crit_yaml}
  protected_ips: $(yaml_list "$PROTECTED")
capture_interfaces:
  - {name: span, type: af_packet, iface: ${CAPTURE_IFACE}}
placement: {primary_tap: span, secondary_tap: span, asymmetric_risk: medium}
monitored_vlans: [unconfigured]
unmapped_vlans: []
has_nat: false
brain: {llm_endpoint_env: SENTINEL_LLM_API, timeout_s: 8, hard_cutoff_s: 5}
actuators:
  - {type: nftables_local}
autonomy_level: 0
enforcement_dry_run: true
limits: {max_blocks_per_min: 5, max_blocks_per_hour: 20, default_ttl_min: 30}
policy:
  auto_act_threshold: 0.95
  human_approval_threshold: 0.80
  report_threshold: 0.50
  approval_timeout_minutes: 15
  report_timeout_minutes: 30
  report_fallback_actions: [throttle_src]
  min_risk_score: 0.20
  suppress_engine_events: true
  suppress_signature_ids: []
critical_response: {enabled: true, min_score: 0.80, deadline_minutes: 15}
audit_store: {path: /var/lib/sentinel/audit.sqlite}
ops_ui:
  enabled: true
  bind: "127.0.0.1:8080"
  auth_token_env: SENTINEL_OPS_UI_TOKEN
  allowed_ports: [8080]
  auth_mode: accounts
EOF
fi

say "4/9 Capture interface in promiscuous mode (persists across reboots)"
cat > /etc/systemd/system/sentinel-span.service <<EOF
[Unit]
Description=Sentinel capture interface up + promiscuous
Before=docker.service
[Service]
Type=oneshot
ExecStart=/usr/sbin/ip link set ${CAPTURE_IFACE} up promisc on
RemainAfterExit=yes
[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload && systemctl enable --now sentinel-span >/dev/null

say "5/9 Build + self-test + config check"
docker compose build -q
docker compose run --rm sentinel selftest
docker compose run --rm sentinel ctl config validate /etc/sentinel/config.yaml

say "6/9 systemd: service, daily rule update, daily backup"
if [[ "$APP_DIR" != /opt/sentinel-app ]]; then
  for f in infra/sentinel.service infra/sentinel-rules-update.service infra/sentinel-backup.service; do
    sed "s#/opt/sentinel-app#${APP_DIR}#g" "$f" > "/etc/systemd/system/$(basename "$f")"; done
else
  cp infra/sentinel.service infra/sentinel-rules-update.service infra/sentinel-backup.service /etc/systemd/system/
fi
cp infra/sentinel-rules-update.timer infra/sentinel-backup.timer /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now sentinel sentinel-rules-update.timer sentinel-backup.timer >/dev/null

say "7/9 Waiting for containers, then downloading Suricata rules (ET Open)"
for i in $(seq 1 60); do
  docker compose ps --status running --services 2>/dev/null | grep -q suricata && break; sleep 5; done
docker compose exec -T suricata suricata-update --no-test || warn "rule download failed (Internet/proxy?) — retry: sudo systemctl start sentinel-rules-update"
docker compose restart suricata >/dev/null

say "8/9 Firewall"
if [[ "$(ask "Lock the host to SSH+HTTPS from: ${ALLOW_CIDRS}? (y/n)" y)" == y ]]; then
  ALLOW_CIDRS="$ALLOW_CIDRS" ./infra/firewall.sh
else
  warn "firewall skipped — run later: sudo ALLOW_CIDRS=\"...\" ./infra/firewall.sh"
fi

say "9/9 First admin account"
for i in $(seq 1 30); do docker compose exec -T sentinel true 2>/dev/null && break; sleep 3; done
docker compose exec sentinel sentinel --config /etc/sentinel/config.yaml \
  ctl user add "$ADMIN_USER" --role admin || warn "create later: docker compose exec sentinel sentinel --config /etc/sentinel/config.yaml ctl user add NAME --role admin"
docker compose cp proxy:/data/caddy/pki/authorities/local/root.crt ./sentinel-root-ca.crt 2>/dev/null \
  && echo "root certificate saved: ${APP_DIR}/sentinel-root-ca.crt" || true

cat <<EOF

────────────────────────────────────────────────────────────
 Sentinel is running (observe-only: dry-run, autonomy 0).
 Open:   https://${SITE_ADDR}       (from the LAN or the VPN)
 Login:  ${ADMIN_USER}  → set your password + enrol the authenticator app
 Remove the browser warning: install sentinel-root-ca.crt on operator devices.
 Status: docker compose ps     Logs: docker compose logs -f sentinel
 Check:  docker compose exec sentinel sentinel ctl audit verify /var/lib/sentinel/audit.sqlite
 Next:   Telegram alerts (notifiers in config.site.yaml), 14-day learning.
────────────────────────────────────────────────────────────
EOF
