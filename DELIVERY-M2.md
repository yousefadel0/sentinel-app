# DELIVERY — M2: Correlator & Baseline Engine (§10-M2)

**Commit:** `M2: correlator & baseline — gap-chain incidents, rolling k-sigma thresholds, seasonal calendar`
**Base:** M1 (`3436f53`) · **Suite:** 143 passed (52 M0 + 43 M1 + 48 M2) · **Coverage TOTAL 96% ≥ 85%**

---

## Acceptance gates (§10-M2) — test-proof table

| Gate | Proof (test → assertion) |
|---|---|
| **A: fixture chains merge into SINGLE incidents** | `test_correlator.py::test_brute_force_burst_merges_into_single_incident` — 7-alert SSH brute-force fixture (5-min gaps, 30 min span) ⇒ exactly ONE incident; `test_cross_family_merge_union_signals_order_stable` — scan→auth_fail_burst→beacon_periodic merge ACROSS families with order-stable signals union; `test_gap_measured_from_last_alert_not_first` pins the chain rule. |
| **B: thresholds shift correctly on seasonal override dates** | `test_baseline_engine.py::test_threshold_doubles_under_x2_override_after_ramp` — ×2 override ⇒ threshold exactly ×2 after ramp; `test_ramp_day0_neutral_day14_full_target` — day 0 = 1.0, day 7 = midpoint 1.5, day 14 = full target; `test_ramp_holds_until_end_date_then_back_to_neutral` — plateau then expiry ⇒ neutral; `test_before_start_date_pure_neutral_regardless_of_history`. |

## Operator reminders #1–#3 — both directions / loser-loses / shared error format

1. **Negative correlation paths exist:** `test_gap_over_window_splits_chain_into_two_incidents` (16-min gap ⇒ TWO incidents), `test_same_dst_different_src_stays_separate`, `test_same_src_different_dst_stays_separate`, boundary pair `test_exactly_window_gap_merges_and_one_second_more_splits` (900 s merges / 901 s splits).
2. **Overlap ⇒ LAST in file order wins + ONE warning line, loser never partially applies:** engine-side `test_overlapping_overrides_last_in_file_wins_no_partial_apply` (multiplier == winner's 1.5, NOT loser's 3.0, not a blend; `boot_warnings == 1`); calendar-side `test_overlap_last_in_file_wins_with_warning_line` (+ structured JSON log record asserted via caplog). Non-overlap control: `test_adjacent_not_overlapping_entries_no_warning`.
3. **Calendar refuse-boot matrix with the EXACT shared format** (`ConfigError`, offending key + valid keys + literal `(ref §8)`): unknown top-level key · unknown extra key inside entry · missing required date field · invalid ISO date · end < start · multiplier 0 / negative / NaN / inf / string / bool · entry-not-mapping · overrides-not-list · top-level-not-mapping · broken YAML syntax — all in `test_baseline_calendar.py::test_invalid_calendar_refuses_boot_with_shared_error_format[*]`.

## Standing decisions folded in

- **D1 injected clock:** `BaselineEngine(clock, calendar_path)` — no `datetime.now()` anywhere in `sentinel/baseline/`; `FakeClock` simulates any 14-day window instantly, including override dates and ramp boundaries (day 0 / day 7 / day 14 / plateau / expiry).
- **D2 separate `seasonal_calendar.yaml`:** sibling file, §8 schema untouched. Present-but-invalid ⇒ `ConfigError` in the main loader's exact style (reused exception, same message grammar, same `(ref §8)` citation — no second error style). Absent file ⇒ neutral multipliers + exactly ONE structured warning line at boot (`test_absent_file_yields_neutral_and_one_structured_warning` asserts both the returned warning list AND the JSON log record).

## Rule 4 guard (zero decision-engine leakage)

`test_threshold_shape_has_no_decision_engine_fields` pins `Threshold.__dataclass_fields__ == {signal_family, mean_rate, sigma, threshold, seasonal_multiplier, window_days_observed}` — no score/action/playbook fields exist. Correlator emits only `Incident{incident_id, src_ip, dst_ip, alerts, first_ts, last_ts, signals}`.

## Frozen-inputs proof (rule 4) — measured, not asserted

```
$ git diff --stat 3436f53..HEAD -- sentinel/models.py sentinel/capture/
(empty output → zero changes to models + capture during M2)
$ git status --short   # before commit: only NEW untracked files; no tracked file modified
?? sentinel/baseline/  ?? sentinel/correlator/  ?? tests/fixtures/calendar/
?? tests/test_baseline_calendar.py  ?? tests/test_baseline_engine.py  ?? tests/test_correlator.py
```

Note on range choice: `cd553ba..HEAD` necessarily shows capture/* as *additions* because that range spans M1, which CREATED the capture layer (M0 had no capture/). The honest frozen-baseline for M2 is M1's accepted HEAD `3436f53`, and against it the filtered diff is empty. `sentinel/models.py` is additionally empty across the full `cd553ba..HEAD` range (untouched since M0).

## New files (12)

| Path | Purpose |
|---|---|
| `sentinel/correlator/__init__.py` · `correlator.py` | Gap-chain correlator; `DEFAULT_CORRELATION_WINDOW_S = 900`; deterministic uuid5 incident ids |
| `sentinel/baseline/__init__.py` · `engine.py` | Rolling 14-day per-family baseline; `K_SIGMA = 3`; injected clock; ramp math |
| `sentinel/baseline/calendar.py` | Fail-closed calendar loader reusing `ConfigError` + `(ref §8)` format |
| `tests/test_correlator.py` (13) · `tests/test_baseline_engine.py` (15) · `tests/test_baseline_calendar.py` (20) | 48 new tests proving gates A/B + reminders 1–3 |
| `tests/fixtures/calendar/{empty,scan_x2}.yaml` | Neutral + ×2 seasonal fixtures |

## Assumptions / notes

- **A1:** Correlation window not yet config-wired (config schema §8 frozen; CLI wiring lands with M6 integration milestone) — exposed as documented module constant + constructor arg.
- **A2:** Threshold formula pinned by tests: `(mean_daily + k·σ_population) × multiplier(t)` over the trailing 14 days ending today inclusive; zero-history family ⇒ all-zero components, no crash (documented behavior).
- **A3:** Seasonal ramp is linear day 0 → day RAMP_DAYS(=14), then holds to end_date. Overlap resolution: LAST file-order entry wins entirely (no blending), warned once per overlapping pair.

## Known limits (deferred by design)

- Incidents are in-memory per call; persistence/audit-store integration arrives with later milestones.
- Calendar supports date-based overrides only (no time-of-day); multipliers apply per signal family name exactly as written in the file.
