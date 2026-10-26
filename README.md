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
python3 -m venv .venv && . .venv/bin/activate   # Python 3.11+ required (§8 pin)
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
