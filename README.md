# Sentinel

Autonomous AI network defense software appliance — portable, self-contained,
SPAN-based (never inline), wire-anchored (P3). See `Project.md` for the
canonical master document (single source of truth).

## Status

**ACTIVE MILESTONE: M0 — Scaffold & contracts**

Repo layout, strict config loader + validator (full §8 schema), structured
JSON logging, CLI with dry-run default true, and the two adapter ABCs
(`DataSource`, `Actuator`). No detection/decision/actuation logic yet.

## Install (dev)

```bash
python3 -m venv .venv && . .venv/bin/activate   # Python 3.9 - 3.14 supported (CI-tested on every version)
pip install -e '.[dev]'
```

## CLI surface (M0)

```bash
sentinel --config config.yaml          # boot check: load+validate, exit 0/1
sentinel ctl config validate <path>    # validate a config file explicitly
sentinel --version                     # print version
```

Global flag `--dry-run` defaults **TRUE** (G2 / P5); `--no-dry-run` opts out.
Config validation is STRICT and fail-closed: unknown or missing keys at any
level refuse boot with an error naming the offending key, the valid keys,
and reference "§8".

## Shadow pilot runbook (M6)

Replay a deterministic attack slice through the full shadow loop — capture →
correlate → decide → gated receipts — with ZERO SIEM involved (P3):

```bash
# 1. Generate a deterministic ddos-volumetric slice (events + manifest):
mkdir -p capture
python - <<'PY'
from pathlib import Path
import json
from tools.make_fixtures import build_slice
events, manifest = build_slice(seed=42)
Path("capture/gen.eve.jsonl").write_text("\n".join(json.dumps(e) for e in events))
Path("capture/manifest.json").write_text(json.dumps(manifest, indent=2))
PY

# 2. Run the shadow pilot (SHADOW-ALWAYS: executes nothing, G2/P5).
#    The pilot persists every decision + verbatim pair, so it requires an
#    `audit_store.path` block (§8/D5) — derive a pilot config from the
#    committed fixture and append one:
python - <<'PY'
import yaml
cfg = yaml.safe_load(open("tests/fixtures/valid_config.yaml"))
cfg["audit_store"] = {"path": "capture/audit.sqlite"}
yaml.safe_dump(cfg, open("pilot_config.yaml", "w"), sort_keys=False)
PY

python -m sentinel.pilot.runner \
    --config pilot_config.yaml \
    --capture-dir capture \
    --manifest capture/manifest.json   # replay-path MTTD (Q1 split)

# 3. KPIs print as JSON: mttd_replay_seconds, fp_rate (honest n/m),
#    actions, rollbacks, llm_latency_ms, decisions_by_outcome.
```

Every decision, verbatim LLM prompt/response pair (G7), action intent and
rollback lands in the append-only SQLite audit store configured under
`audit_store.path` (§8/D5). The pilot accepts `--no-dry-run` for CLI parity
but never executes an action regardless.

## Ops UI runbook (M7)

The Ops UI is an **optional** module (`pip install '.[ops-ui]'`; already
installed by `infra/bootstrap.sh`). There is no CLI wiring yet — standalone
`serve()` with a hand-built store is the only launch path today.

### Launch (verified end-to-end at ef0b2b9)

```python
# scripts/run_ops_ui.py-style launcher — the ONLY sanctioned incantation:
import os
os.environ["SENTINEL_OPS_UI_TOKEN"] = "choose-a-long-random-secret"   # REQUIRED, fail-closed
from sentinel.config.loader import load_config            # whole-config validation incl. bindcheck
from sentinel.auditstore.store import Store               # NOTE check_same_thread=False — REQUIRED
from sentinel.ui.app import serve

cfg = load_config("config.yaml")                          # wants a LOADED dict; a path raises TypeError
cfg["ops_ui"]["enabled"] = True                           # never on by default — explicit opt-in
serve(cfg, store=Store("audit.sqlite3", check_same_thread=False))
```

Gotchas, each verified the hard way:

- `uvicorn sentinel.ui.app:app` fails — `create_app` is a factory; there is
  no module-level `app`.
- `serve("config.yaml")` raises `TypeError` — pass the **loaded** dict from
  `load_config()`, not a path.
- `Store(path)` without `check_same_thread=False` crashes under FastAPI's
  threadpool with `sqlite3.ProgrammingError` (uvicorn serves sync endpoints
  on worker threads).
- Startup prints **nothing**: uvicorn runs at `log_level="warning"`, so a
  successful boot looks hung — poll the port instead of waiting for a banner.
- Boot refuses if `ops_ui.enabled` is false or the token env var named by
  `auth_token_env` is unset/empty.

### Security matrix (curl-proven)

```bash
export SENTINEL_OPS_UI_TOKEN='choose-a-long-random-secret'
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8080/kpis \
    # → 401 (no header)
curl -s -o /dev/null -w '%{http_code}\n' -H "X-Sentinel-Token: $SENTINEL_OPS_UI_TOKEN" \
    http://127.0.0.1:8080/kpis                                  # → 200
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8080/static/htmx.min.js

## Attack reports and threat intelligence

The shadow pilot now writes a per-run JSON report and a readable Arabic HTML report. Each incident includes the observed signal family, the decision and reason, whether Sentinel executed an action (the pilot always reports `false`), evidence file references, and a **candidate** ATT&CK technique. The technique mapping is explanatory context and does not train a model or alter the decision engine. CVEs are never guessed from an attack label: optional NVD enrichment only looks up CVE identifiers already present in event evidence.

### Windows / PowerShell

Run from the project folder with the project's Python environment active (or call its Python executable directly):

```powershell
# Optional: download MITRE's official Enterprise ATT&CK catalog for richer descriptions
.\.venv\Scripts\python.exe -m sentinel ctl intel sync-attack --output data/attack/enterprise-attack.json

# Replay the capture files and generate reports without making network requests
.\.venv\Scripts\python.exe -m sentinel.pilot.runner `
  --config pilot_config.yaml `
  --capture-dir capture `
  --manifest capture/manifest.json `
  --report-dir reports `
  --attack-catalog data/attack/enterprise-attack.json

# Open reports\latest.html in a browser. Each run also gets its own .json and .html.
```

To also look up CVEs found in the capture, add `--enrich-vulnerabilities`. This contacts the read-only NIST NVD API; `NVD_API_KEY` is optional and can be set in the current PowerShell window with `$env:NVD_API_KEY = "your-key"`. Without the ATT&CK cache the report still works using the small curated technique-ID mapping and clearly marks that the full catalog was not synced. The Ops UI can show the latest report when launched with `report_dir=Path("reports")`; its `/reports/latest` route uses the same token authentication as the dashboard.
    # → 200 (sole unauthenticated route)
```

Auth is **header-only** (`X-Sentinel-Token`, constant-time compare) — NOT
`Authorization: Bearer`. No cookies/sessions ⇒ CSRF-immune; tokens in query
strings are rejected. Because `/` itself is token-guarded, plain browser
navigation cannot authenticate **by design**.

### Route inventory (complete)

| Route | Method | Auth | Purpose |
|---|---|---|---|
| `/` | GET | token | HTML shell (htmx polling dashboard) |
| `/health/capture` | GET | token | capture health JSON |
| `/approvals` | GET | token | pending human-approval queue |
| `/approvals/{id}/approve` · `/deny` | POST | token | WRITE via `Engine.resolve` seam (409 standalone) |
| `/incidents/recent` | GET | token | recent incidents JSON |
| `/kpis` | GET | token | KPI counters (P5 names) |
| `/static/htmx.min.js` | GET | none | static asset |

There is no `/api` prefix; auth is enforced per-handler, so unknown paths
fall through to FastAPI's default 404.

### Accessing the UI from outside a container (tunnel recipe)

The bind is loopback-only by hard invariant (`bindcheck` rejects routable
hosts unconditionally). From an operator workstation:

```bash
ssh -N -L 8080:127.0.0.1:8080 user@sentinel-host   # then point curl at localhost:8080
```

For interactive browsing, inject the header with a local reverse proxy or a
browser extension — never relax the server-side guard.

## Tests

```bash
pytest                       # full suite
pytest --cov=sentinel        # coverage (target ≥85% core; 100% on validator)
```

## Live shadow daemon (Phase 1)

`sentinel run` tails Suricata `eve.json` and Zeek `conn/dns/ssl/notice.log`
as the sensors write them (restart- and rotation-safe offsets in
`.sentinel-offsets.json`), correlates, decides, and records every decision
(`case_id="live"`) in the audit store. It is SHADOW-ONLY: nothing executes.
Capture health (including `degraded` when a log goes quiet and Suricata
kernel drops) is published to `<capture-dir>/live-health.json`.

```bash
sentinel --config config.yaml run --capture-dir /var/log/suricata
```

`docker compose up -d` (see `docker-compose.yml`) runs Suricata + Zeek +
Sentinel against one SPAN interface (`CAPTURE_IFACE`).

## Behavioral detectors + evaluation (Phase 3)

`sentinel/detectors/` turns raw Zeek `conn`/eve `flow` records and
DNS-derived tokens into the attack signals the Decision Engine understands
(scan, brute force, volumetric DDoS, C2 beaconing, DNS tunneling) as Tier B
alerts. Raw records only feed the detectors; only signature hits and
detector output enter correlation, so ordinary traffic never creates incidents.

```bash
python -m sentinel.evaluation.harness    # per-family recall/precision/MTTD
```

The harness uses seeded SYNTHETIC scenarios (regression guard, not a
substitute for real-capture evaluation). Known trade-off: beacon detection
needs 12 regular connections, so MTTD for a 60-120 s beacon is 12-24 minutes.
New attack types beyond the five v1 families need a scope change in
`Project.md` first (engine enum, playbooks and brain schema are pinned).

## LLM brain hardening (Phase 4)

* Packet-derived fields sent to the model are validated (`src_ip`/`dst_ip`
  must be IP addresses, `protocol`/`vlan_tag`/`direction` short tokens,
  hostile `case_id` replaced); anything else is dropped, not forwarded.
* `sentinel.brain.benchmark.run_benchmark` runs the same labeled cases
  through several endpoints (one env var each) and reports schema-valid
  rate, attack-type accuracy, playbook-safety rate, latency p50/p95 and
  optional cost.
* `sentinel run` triages ambiguous incidents (notify/human/escalate)
  ADVISORILY when `brain.llm_endpoint_env` is set: rate-capped, off the
  capture thread, recorded verbatim in `llm_pairs`, never altering a decision.

## Integrations (Phase 5)

Optional config blocks (secrets always come from environment variables):

```yaml
notifiers:
  - {type: webhook, url_env: SLACK_WEBHOOK_URL, format: slack}   # slack|teams|generic
  - {type: telegram, url_env: TG_BOT_TOKEN, chat_id: "123456", approvals: true}
siem:
  enabled: true
  inbound:  {enabled: true, source: wazuh, alerts_file: /var/ossec/logs/alerts/alerts.json,
             api_url: "-", poll_interval_seconds: 5, token_env: "-"}
  outbound: {enabled: true, endpoint: "syslog+udp://siem.local:514",   # or https://...
             batch_size: 100, poll_interval_seconds: 10, token_env: SIEM_TOKEN}
```

* **Notifications** go out for human-approval / escalate / notify / auto
  outcomes: deduped, rate-capped, off the capture thread, never fatal.
* **Telegram approvals** (`/approve <id>`, `/deny <id>` from the one
  configured chat) use outbound long-polling only and resolve through the
  same `Engine.resolve` seam as the Ops UI (audit `case_id="telegram"`).
* **SIEM inbound** tails Wazuh `alerts.json`; evidence is **Tier C** and can
  never trigger an automated action. **Outbound** exports verdicts as CEF
  (syslog UDP/TCP) or JSON/HTTPS with a persisted high-water mark.

Not included: vendor firewall actuators (pfSense/Palo Alto/FortiGate) and
SMTP — they cannot be validated without the real systems, and an untested
actuator that talks to a production firewall is not something to ship.

## Production hardening (Phase 6)

* **Tamper-evident audit:** every audit row is linked into a SHA-256 hash
  chain (`audit_chain`, append-only). `sentinel ctl audit verify <db>`
  recomputes it and detects edited, deleted, spliced and out-of-band rows.
  Rows that predate the chain are reported as `legacy_unchained`. Record
  the printed `head` OUTSIDE the file and pass `--expect-head` later:
  truncating the tail is only detectable against an external anchor.
* **Metrics:** the daemon writes `<capture-dir>/sentinel.prom` in Prometheus
  text format (node_exporter textfile collector) — no listening port.
* **Image:** `infra/Dockerfile` has a HEALTHCHECK on `live-health.json`
  freshness. Built and smoke-tested on Python 3.11 (boot, tail, decision,
  audit verify, health = healthy).
* **Throughput (detectors only, one core, synthetic flows):**
  `python -m sentinel.evaluation.perf 3000 100` → ~290 ms per 1-second
  cycle at 3,000 flows/s, so roughly 5-8k flows/s per process is the
  ceiling; beyond that shard by sensor. Parsing cost is additional.
  Beacon history is bounded by `max_tracked` (200k events).

Not included: Helm chart / OVA / HA pair — they need target infrastructure to
validate and are deliberately not shipped untested.

## Ops UI v2 (dashboard + analyst control)

Six tabs — **Overview** (KPIs, decisions over time, top sources/targets, attack
types, autonomy-readiness gate), **Incidents** (filter by outcome/tier/type/IP/
text/score/analyst verdict, paging, CSV export, side-panel with the full
decision timeline, evidence references and MITRE candidates), **Approvals**
(pending queue with source/target, history), **Sources** (live sensor health),
**Audit** (search + one-click hash-chain verification) and **Settings**
(read-only, secrets reduced to "is the env var set").

Control is deliberately narrow: the only writes are (1) approve/deny through
`Engine.resolve` (unchanged) and (2) analyst verdicts/notes
(`POST /incidents/{id}/annotate`), appended to the hash-chained audit store.
Verdicts never reach the engine, so they cannot change or trigger an action;
they do feed the analyst false-positive rate that gates any autonomy upgrade.
Settings are not editable from the UI on purpose.

The daemon now records who/what/where per incident (`incident_context`:
src/dst, signals, evidence `file#line` references, MITRE candidates). Incidents
recorded before this version show no context.

## Enforcement (mitigation) — off by default

`sentinel run` is SHADOW by default. Acting on the network needs ALL of:
`--no-dry-run`, `autonomy_level >= 1` in the config (the CLI refuses live mode
at L0), a configured actuator, and a decision that reaches an enforceable
outcome. Every decision then passes `sentinel.actuation.Executor`:

| gate | rule |
|---|---|
| autonomy | auto outcomes need L2+, human-approved (UI / Telegram) need L1+ |
| dry-run | default; records the intent in `actions` (verdict `dry_run`), executes nothing |
| validator (G6) | §3.1 chain + engine verdict + G3 TTL <= 60 min |
| hourly cap | `limits.max_blocks_per_hour`, also applies to approved actions |
| actuator | must exist and be healthy, otherwise an honest `failed` / `no_actuator` row |

Every branch writes an `actions` row (`executed`, `dry_run`, `withheld_autonomy`,
`rejected_g6`, `rate_limited`, `no_actuator`, `failed`), hash-chained like the rest
of the audit store. Approving from the Ops UI or Telegram runs the same executor.

Actuators (`actuators:` in the config):
* `webhook_soar` — DDoS playbook: asks the operator's SOAR/firewall to mitigate
  upstream for the victim (Sentinel is SPAN-only; it never blocks that traffic
  itself). Sends `Authorization: Bearer $SENTINEL_SOAR_TOKEN` when set.
* `nftables_local` — block / throttle / quarantine via three timeout sets, enforced
  in `input` and `forward` chains. Validated against real nftables 1.1 in a
  privileged container (`tests/test_nft_real.py`). Expiry is done by the kernel;
  `sentinel ctl rollback --all` flushes everything from any process.
  On a SPAN-only sensor this only protects the sensor host itself.

Run the real-nft tests where they can execute:

```bash
docker run --rm --cap-add NET_ADMIN -v "$PWD":/src <image with python + nftables> \
  sh -c "cp -r /src /w && cd /w && pip install -q -e '.[dev]' && python -m pytest tests/test_nft_real.py -o addopts= -q"
```

### Known limit of the current scoring (decision needed)
With the pinned formula `confidence x criticality x severity/5` and the 0.70 band,
the best case per family (confidence 1.0) is: DDoS on a high/critical asset
-> human approval / auto-act; brute force and C2 -> at most 0.68 (high) or 0.80
(critical); scan and DNS tunneling -> never above 0.60. G1 also judges the
VICTIM (`dst`), so brute force on a critical server escalates to a human instead
of blocking the attacker. Net: today only the DDoS playbook can lead to an
executed action; the others are alert/escalate-only. This is a guardrail and
scoring policy choice, so it is deliberately unchanged here.
