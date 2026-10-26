# DELIVERY — M4: Validator & Actuators (§10-M4)

**Commit:** `M4: validator & actuators — single-source §3.1 gate, nftables_local + webhook_soar, dry-run parity`
**Base:** M3 (`b800200`) · **Suite:** see verbatim pytest line below · **Coverage TOTAL 96% ≥ 85%**

```
============================= 249 passed in 1.26s ==============================
```

(52 M0 + 43 M1 + 48 M2 + 78 M3 + 28 M4 = 249; arithmetic reconciles with the
accepted M3 close at 221.)

---

## Binding checklist — one-line proofs

1. **Single-source validator w/ pre_band/post_band intact** — `sentinel/validator/__init__.py` re-exports `CHAIN_ROWS`, `ChainRow`, `Phase` unchanged from `sentinel.decision.chain`; `tests/test_validator.py::test_single_source_rows_reexported_unchanged` pins identity of the table and both phases.
2. **nft absence ⇒ health=down honestly** — `NftablesLocalActuator.health()` probes `which("nft")` then `nft list tables`; `tests/test_actuators_nftables.py::test_health_down_when_nft_absent` asserts `{"status": "down", ...}` with no fake success.
3. **Webhook offline ⇒ log_only degrade, no crash, bounded retry only** — `MAX_ATTEMPTS=3` with 0.5 s/1.0 s backoff then `ActionResult(ok=False, detail="log_only degrade...")`; `tests/test_actuators_webhook.py::test_offline_degrades_to_log_only_after_bounded_retries` asserts exactly 3 attempts, sleeper calls `[0.5, 1.0]`, no exception escapes.
4. **TTL>60 rejected AT actuator layer** — defense-in-depth check runs BEFORE validation; `tests/test_actuators_nftables.py::test_ttl_over_60_rejected_at_actuator_layer` (and validator-side raise in `test_validator.py`) prove G3 twice, independent of engine caps.
5. **Unknown action strings rejected before execution** — `Validator.validate` raises `ValidationError` for any string outside `ActionType` before any actuator call; `tests/test_validator.py::test_unknown_action_string_raises_pre_execution`.
6. **Parity: engine rec == validated action == actuator receipt** — `tests/test_parity.py`: brute-force Tier-A flow pins `dec.recommendation.action == action.type.value == "block_ip_temp"` with receipt `ok=True`; quarantine flow pins the same triple for `"quarantine_asset"` ttl 60; escalate flow proves non-enforceable outcomes never reach an actuator.
7. **git status declared before commit titled "M4: …"** — see Frozen-inputs proof below; delivery report includes this file.

## Acceptance gate (§10-M4) — test-proof table

| Gate | Proof |
|---|---|
| **No code path reaches an actuator without passing the validator (test-proven), rejection paths included** | Both actuators take a REQUIRED shared `Validator` instance and wrap it as `_GuardedActuator` (`tests/test_validator.py::test_guard_blocks_and_passes`); nft `execute()` order = TTL defense → validate (no-crash wrap ⇒ `G6 gate error`, never a traceback) → health probe → rule add; webhook validates payload schema pre-POST. Rejection paths: G6 rejection inside actuator blocks any subprocess call (`test_g6_rejection_inside_actuator_blocks_nft_call` asserts empty runner calls). |

## New files (9)

| Path | Purpose |
|---|---|
| `sentinel/validator/__init__.py` | §3.1 single-source gate: strictness, TTL ceiling, chain walk over re-exported CHAIN_ROWS, engine_outcome fact gate, `_GuardedActuator`. |
| `sentinel/actuators/__init__.py` | Actuator package exports. |
| `sentinel/actuators/nftables_local.py` | Temp rules w/ kernel `timeout`, honest health probe, idempotent rollback, `pending_expiry()`, injectable `which_fn`/`runner`/clock. |
| `sentinel/actuators/webhook_soar.py` | Schema-validated POST, bounded retry/backoff, offline ⇒ log_only degrade, quiet rollback noop. |
| `tests/test_validator.py` | 12 tests — single source, G6 guard, rejection matrix, TTL raise. |
| `tests/test_actuators_nftables.py` | 8 tests — health honesty, TTL defense, rule shape incl. rate_pps, add-failure rc surfaced, rollback idempotence. |
| `tests/test_actuators_webhook.py` | 5 tests — schema strictness (target_ip required for aggressive), retries, degrade, success. |
| `tests/test_parity.py` | 3 tests — triple-agreement parity on block + quarantine; escalate never enforced. |
| `DELIVERY-M4.md` / `DELIVERY-M3.md` (backfill) | This report + restored M3 gate record. |

## Modified files (2)

| Path | Change |
|---|---|
| `infra/Dockerfile` | §9-I6: committed `apt-get install nftables` layer so the actuator binary ships in-image. |
| `infra/bootstrap.sh` | §9-I6: idempotent nftables install step + honest "NOT PRESENT" notice for sandboxes without it. |

## Frozen-inputs proof (rule 4) — measured, not asserted

```
$ git status --short   # before commit
 ?? DELIVERY-M3.md   ?? DELIVERY-M4.md   ?? sentinel/validator/
 ?? sentinel/actuators/   ?? tests/test_validator.py
 ?? tests/test_actuators_nftables.py   ?? tests/test_actuators_webhook.py
 ?? tests/test_parity.py
 M infra/Dockerfile   M infra/bootstrap.sh
(new-vs-modified declared: 7 new paths + 1 new doc pair; exactly 2 tracked
files modified, both infra tooling per §9-I6 — zero changes to
sentinel/decision/, sentinel/capture/, sentinel/models.py)
```

## Known limits

- Sandbox has no kernel nft support ⇒ runner-based tests inject fakes; the
  real-binary path is exercised at M6 packaging (image carries nftables).
- Webhook auth uses `token_env` indirection; secret rotation UX is ops scope.
- Parity seam maps only enforcement playbooks (`block_ip_temp`,
  `quarantine_asset`) to ActionTypes by design; notify/recommend recs raise
  loudly if ever wired to an actuator.
