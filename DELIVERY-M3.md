# DELIVERY — M3: Decision Engine in dry-run mode (§10-M3)

**Commit:** `b800200` — `M3: decision engine — §3.1 single-row chain, banding & tier caps, playbooks, autonomy controller, sliding-window rate limiter`
**Base:** M2 (`6b01ec5`) · **Suite at close:** 221 passed (52 M0 + 43 M1 + 48 M2 + 78 M3) · **Coverage TOTAL ≥ 85%**

> Backfilled at M4 per operator reconciliation: the arithmetic 52+43+48+78=221
> was accepted as closing M3; this document restores the gate-proof record.

---

## Acceptance gates (§10-M3) — test-proof table

| Gate | Proof (test → assertion) |
|---|---|
| **Decision table 100% unit-tested incl. allowlist-rejection cases** | `tests/test_decision_engine.py` (27 tests): every §3.1 row fired both directions; allowlist rejection via `critical_assets` hit ⇒ escalate path with verbatim audit event; blind-spot VLAN ⇒ exactly ONE `alert_from_blind_spot_vlan` event and a single −0.20 penalty (no double-apply across pre/post passes); NAT fallback fires only when `nat_resolved_src is None AND src_private_outside_local`; liveness ≠ alive ⇒ no enforcement outcome. Boundary pins in `test_decision_scoring.py`: band edges 0.90/0.70 exact, tier caps A/B/C enforced by `_weakest_tier`. |
| **Dry-run parity of narration ("would do X because Y")** | Every `Decision` carries `recommendation.because` verbatim from `PLAYBOOKS` (P6); `test_decision_playbooks.py` (15 tests) pins all five v1 attack types to their §6 playbook rows, TTLs ≤ 60 (G3), and the operator-pinned enum value `recommend_upstream_mitigation` for DDoS (never blind-block distributed sources locally). |

## §3.1 single-row restructure note

The six ordered chain steps live in ONE table — `sentinel/decision/chain.py::CHAIN_ROWS`
(binding 1: no second copy of the walk anywhere). Each row is
`ChainRow(name, phase, effect)` with `phase ∈ {PRE_BAND, POST_BAND}`:

- **pre_band rows touch ONLY the score:** `nat_fallback` (−0.15, step 1c),
  `vlan_blind_spot` (−0.20, step 3).
- **post_band rows touch ONLY outcome/action:** liveness gate,
  critical-asset allowlist rejection, asymmetric downgrade (block→throttle_src),
  rate-limit breach.
- The engine evaluates each row exactly once (`_run_pre_band` / `_run_post_band`);
  fired rows emit their glossary-controlled audit event exactly once (P6).
  M4's Validator re-exports this same table unchanged — the validator IS the
  chain, not a parallel implementation.

## G1 rejection matrix (aggressive actions vs. facts)

| Fact state | Aggressive action result |
|---|---|
| `liveness != "alive"` | REJECTED (no enforcement on unconfirmed target) |
| target ∈ `critical_assets` | REJECTED (allowlist; escalate instead) |
| `rate_limit_breach = True` | REJECTED (G4 sliding-window cap reached) |
| asymmetric risk high + BLOCK_IP_TEMP | DOWNGRADED to throttle_src (never blind-block) |
| engine outcome ∉ {auto_act, auto_throttle} | REJECTED (escalate/human/notify/log are not enforceable) |

All six rows proven in `test_decision_chain.py` + `test_decision_engine.py`;
the same matrix is re-proven at the enforcement boundary by M4's
`tests/test_validator.py`.

## Calibration table (Q2-accepted defaults, §8 seam for overrides)

| Attack type | Severity default | Playbook (§6 verbatim) |
|---|---|---|
| scan | 2 | notify_only |
| brute_force | 4 | block_ip_temp (ttl 30m, target src) |
| ddos_volumetric | 5 | recommend_upstream_mitigation (upstream via SOAR) |
| c2_beacon | 4 | quarantine_asset (ttl 60m, target dst) |
| dns_tunneling | 3 | notify_only (+ proposed egress rule for human approval) |

Bands on final clamped score: ≥0.90 auto · ≥0.70 human · else log_only.
Tier caps: weakest alert tier wins (`_weakest_tier`). Penalties: NAT −0.15,
blind-spot VLAN −0.20 (additive, clamped to [0,1]).

## Known limits

- Severity defaults are rule-derived; real SIEM enrichment arrives Phase-2 via
  the explicit `severity_override` engine input (deterministic until then).
- Rate limiter is per-engine in-memory; multi-process deployment shares state
  only via future external store (out of v1 scope).
- Autonomy ladder L0–L3 gates outcomes but actuator wiring itself is M4 scope;
  M3 proves decisions, not enforcement.
