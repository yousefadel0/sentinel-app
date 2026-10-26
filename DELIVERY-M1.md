# M1 Delivery Report — Capture Layer

**ACTIVE MILESTONE: M1** · Commit: `M1: capture layer` · Base: cd553ba (M0)

## Scope delivered
First-class capture layer per §4/§10-M1: streaming parsers for Suricata
eve.json and Zeek ASCII logs (conn/dns/ssl/notice), centralized tier map,
per-interface health tracking, file/replay DataSources, commit-only deploy
bootstrap scripts.

## Acceptance-gate proof (§10-M1)

| Gate | Proof |
|---|---|
| Fixtures → typed Alerts | `tests/test_adapters_file.py::test_fixture_yields_typed_alerts_with_full_field_set` parametrized over all 5 adapters; manual run produced frozen `Alert` dataclasses with full §4 field set (`source.adapter/ref`, ips/ports/proto, vlan, asset_hint, signals, confidence_raw/tier, meta). |
| Per-interface health metrics | `CaptureHealthTracker` + `health()` on every adapter: status/heartbeat_ts/packet_drops/coverage_percent/last_alert_ts/source_type/malformed_lines_skipped. Replay honesty enforced by tests: `source_type=="file_replay"`, `packet_drops==0` (documented zero), `coverage_percent is None` (N/A); missing fixture ⇒ `status=="down"` without raising. |
| Coverage ≥85% | `pytest --cov=sentinel`: **TOTAL 96%** (capture pkg: normalizer 97%, eve_parser 95%, zeek_logs 90%, health 100%, adapters_file 95%). |

## Folded items honored
1. **event_type→signals hint**: `_EVE_SIGNAL_HINTS` maps eve `event_type`
   ("alert"→suricata_alert, "dns"→dns_event, …) plus `signature_hit` when an
   alert sub-dict is present — cheap now, consumed by M3 playbooks.
2. **Malformed-line policy (both parsers)**: skip + increment counter surfaced
   via `health()["malformed_lines_skipped"]` (`on_malformed` callback →
   `record_malformed`) + one structured log line per occurrence
   (`eve_malformed_line_skipped`, `eve_non_object_line_skipped`,
   `zeek_row_before_header_skipped`, `zeek_malformed_row_skipped`,
   `zeek_bad_cell_skipped`) + summary line; capture loop never crashes on bad
   input (proven by tests).
3. **Replay heartbeat basis**: fixture mtime when the file exists, else
   ingestion time; documented in adapter docstrings and exposed as
   `heartbeat_basis` ("file_mtime"|"ingestion_time") in health output.

## Assumptions applied
- A1: no §8 schema change — replay adapters constructed programmatically;
  config wiring deferred to M6 harness.
- A2: zeek_ssl/zeek_notice ride the §4 `<future>` extensibility marker.
- A3: deploy scripts are commit-only bootstrap artifacts (Sandbox-First §9-I6);
  they install-if-absent and do NOT start live capture.

## Sandbox-First compliance
No environment changes outside the repo. `infra/suricata-deploy.sh` and
`infra/zeek-deploy.sh` are idempotent install-if-absent bootstrap scripts,
syntax-checked (`bash -n`), executable, with placeholder HOME_NET configs.
File/replay adapters are the legitimate dev route; nothing fakes live capture.

## Test results
95 passed (52 M0 + 43 M1) · coverage 96% total · CLI regression green
(`python -m sentinel --help` rc=0).

## Known limits (honest)
- Zeek `#separator` other than tab is not supported (TSV assumed; directive
  parsed but rejected implicitly by column mismatch → skipped+counted).
- Coverage percent remains a stub until M2 wires asset-touch tracking.
