# DELIVERY — M6: Shadow Pilot Pack (§10-M6)

**Commit:** see Frozen-inputs proof below — `M6: shadow pilot pack — full-loop harness, replay+slice manifest, SQLite append-only audit store, KPI counters, attack/benign generators, docker packaging, README runbook`
**Base:** M5 (`ec494c9`) · **Suite:** verbatim pytest line below · **Coverage TOTAL 95% ≥ 85%**

```
============================== 331 passed in 11.55s ==============================
```

(52 M0 + 43 M1 + 48 M2 + 78 M3 + 28 M4 = 249; + 67 brain-collected at M5 =
316; + 15 pilot tests at M6 = 331 — arithmetic reconciles with the accepted
M4/M5 closes. Collected counts measured via `pytest --collect-only`.)

---

## Binding checklist — one-line proofs

1. **Full-loop harness** — `sentinel/pilot/runner.py::run_pilot(config_path, capture_dir, manifest_path=None)` drives eve-file capture → correlator → decision engine → gated actuation receipts into the audit store, returning computed KPIs; CLI entry `python -m sentinel.pilot.runner --config … --capture-dir … [--manifest …]`; smoke-proven by `tests/test_pilot_runner.py::test_run_pilot_smoke_generator_path`.
2. **MTTD names never blended (Q1)** — virtual/replay-clock detections land ONLY in `mttd_replay_seconds`, wall-clock only in the live metric; pinned twice: `test_pilot_kpi.py::test_mttd_names_never_blended_q1` and `test_pilot_runner.py::test_runner_never_blends_mttd_names_q1`.
3. **CICIDS2017-style replay support** — committed deterministic generators (`tools/make_fixtures.build_slice`, ddos-volumetric slice w/ provenance manifest) + `EveFileDataSource(signal_key=…)` seam feeding base signals; GAP-2 closed with NO silent deferral: `test_t2_ddos_incident_via_slice_manifest_gap2` proves a ddos-class incident through the real `run_pilot` path.
4. **Shadow-always under `--no-dry-run` (G2/P5)** — the pilot accepts the flag for CLI parity but executes nothing regardless; `test_t3_shadow_always_under_no_dry_run` asserts zero executed actions while receipts still record intent.
5. **ZERO SIEM present — proving P3** — `test_t4_zero_siem_e2e_all_sockets_disabled(monkeypatch)` disables every socket and completes the full pipeline e2e; no SIEM client exists anywhere in `sentinel/`.
6. **Append-only audit trail enforced by SQLite itself** — `test_t5_append_only_immutability_real_sqlite_file()` uses the REAL sqlite file + triggers to prove UPDATE/DELETE on decision rows raise, not just an API promise.
7. **G7 verbatim pairs persisted IN the store, byte-exact** — `StorePairSink.append_pair` writes prompt/response halves unmodified; `test_t6_g7_llm_pair_persisted_in_store_byte_exact` re-reads the file and compares bytes; `test_t7_g7_triage_branch_records_pairs_via_runner` proves the fallback-triage branch records its pair through the runner too.
8. **KPI counters** — `sentinel/pilot/kpi.py::compute_kpis(store)`: MTTD (split per Q1), FP-rate counting ONLY benign detections with honest `n`/`m` denominators (`test_fp_rate_counts_only_benign_and_reports_n_m`), actions, rollbacks, LLM latency, decisions-by-outcome tally; empty store ⇒ honest zeros (`test_empty_store_honest_zeros`).
9. **Docker packaging** — `infra/Dockerfile` (committed at M4: python:3.11-slim, pip install `.`, nftables layer, ENTRYPOINT `sentinel`) + new `.dockerignore`; build GAP documented below per Q4 condition-open protocol.

## Acceptance gate (§10-M6) — test-proof table

| Gate | Proof |
|---|---|
| **End-to-end attack contained in shadow mode with full audit trail** | T2 fires a real ddos-volumetric slice through `run_pilot` → incident classified `ddos_volumetric` → §6 playbook recommends `recommend_upstream_mitigation` (operator-pinned enum, never blind local blocks); T3 proves zero executed actions even under `--no-dry-run`; T5/T6 prove the decision + verbatim LLM pairs are immutably persisted. |
| **ZERO SIEM present — proving P3** | T4 completes capture→detect→decide→(gated)act e2e with ALL sockets disabled via monkeypatch; the wire is the only eye. |

## NFT capability probe — honest evidence (in-sandbox)

```
{'status': 'down', 'detail': 'nft probe rc=1: Operation not permitted (you must be root)
netlink: Error: cache initialization failed: Operation not permitted'}
```

The M4 honesty contract holds at M6: the actuator reports DOWN rather than
faking success when the sandbox kernel denies netlink.

## Docker build GAP (Q4 condition-open)

In-session `docker build` is blocked by missing kernel capabilities — both
builders fail identically:

- classic builder (`DOCKER_BUILDKIT=0`): `unshare: operation not permitted`
  (+ tar errors reading `.git` objects);
- BuildKit (`DOCKER_BUILDKIT=1`): bind-mount setup `operation not permitted`.

Daemon itself initializes cleanly (`dockerd --iptables=false --bridge=none`;
API listen confirmed, version 28.5.1). Per Q4 protocol this ships as a
CONDITION-OPEN item: packaging artifacts are complete and committed; the
image build+smoke must be re-run on a host granting CAP_SYS_ADMIN/CAP_NET_ADMIN.
No gate is claimed as passed on this item beyond artifact completeness.

## New files (16 tracked paths + docs pair)

| Path | Purpose |
|---|---|
| `sentinel/auditstore/__init__.py` / `store.py` | D5: SQLite append-only audit store (meta, decisions, llm_pairs, actions, rollbacks, kpi_events) with real-file immutability triggers. |
| `sentinel/pilot/kpi.py` | KPI computation: MTTD split (Q1), FP-rate w/ honest n/m, actions, rollbacks, LLM latency, outcome tally. |
| `sentinel/pilot/runner.py` | Full-loop shadow harness + VirtualClock + StorePairSink + CLI. |
| `tools/__init__.py`, `tools/make_fixtures.py` | Deterministic ddos slice generator (events + provenance manifest), pure/no-I/O core. |
| `tools/attackers/*` (brute_force, dns_tunnel, scan, c2_beacon, common) | Attack traffic eve-record generators. |
| `tools/attackers/benign/*` (http_browse, periodic_dns, ssh_session) | Benign background generators for FP-rate denominators. |
| `tests/test_pilot_runner.py` | 3 tests — smoke path, Q1 non-blending at runner level, D5 fail-closed refusal when `audit_store.path` missing (regression found BY the runbook verification below). |
| `tests/test_pilot_kpi.py` | 5 tests — zeros honesty, Q1, FP n/m, counters, tally. |
| `tests/test_pilot_replay.py` | 7 tests — T1–T7 delivery-chain proofs (see checklist). |
| `.dockerignore` | Build-context hygiene (.git, caches, tests, egg-info, delivery docs). |
| `DELIVERY-M5.md` / `DELIVERY-M6.md` | M5 backfill record + this report. |

## Modified files (3)

| Path | Change |
|---|---|
| `sentinel/capture/adapters_file.py` | Optional `signal_key` seam: when set, a harness-private eve key feeds `normalize()` as a base signal label; default None keeps EXACT M1 behavior (docstring-pinned). |
| `sentinel/config/schema.py` | §8 schema gains optional `audit_store` block (D5): when present, `path` is required and names the SQLite append-only store. |
| `sentinel/pilot/runner.py` | Fail-closed D5 handling: missing/malformed `audit_store.path` ⇒ clear `ConfigError` naming the key + §8 ref (never KeyError, never an unpersisted run); CLI `main()` catches it → stderr message + exit 2. Found by executing the README runbook verbatim during verification. |

## Runbook verification (executed, not asserted)

The README "Shadow pilot runbook" was executed end-to-end in-session:
slice generation (40 events) → `pilot_config.yaml` derived from the committed
fixture + `audit_store` block → `python -m sentinel.pilot.runner … --manifest …`
→ EXIT=0 with REAL ingestion: `incidents: 40`,
`mttd_replay_seconds.avg = 39.0 (n=40)` (Q1 split holds — wall-clock
`mttd_seconds` honest zeros), `decisions_by_outcome: {log_only: 40}`,
`actions_executed: 0`. Note: the audit store is append-only, so re-runs
accumulate; point `audit_store.path` at a fresh file for a clean pass.
This verification surfaced and fixed the runner's KeyError on optional
`audit_store` (see Modified files).

## README runbook

§10-M6 requires a README runbook; added below the CLI surface section
("Shadow pilot runbook (M6)") covering fixture generation → replay run → KPI output.

## Frozen-inputs proof (rule 4) — measured, not asserted

```
$ git status --short   # before commit (verification artifacts capture/ +
                       # pilot_config.yaml removed after the runbook check)
 M README.md
 M sentinel/capture/adapters_file.py
 M sentinel/config/schema.py
 M sentinel/pilot/runner.py
 ?? .dockerignore
 ?? DELIVERY-M5.md     ?? DELIVERY-M6.md
 ?? sentinel/auditstore/   ?? sentinel/pilot/
 ?? tests/test_pilot_kpi.py   ?? tests/test_pilot_replay.py
 ?? tests/test_pilot_runner.py   ?? tools/
(new-vs-modified declared: 9 new paths + docs pair; exactly 4 tracked files
modified — README runbook, one additive capture seam (default-off), one
additive schema block, one fail-closed pilot hardening; zero changes to
decision/, validator/, actuators/, brain/)
```

## Known limits

- Docker image build condition-open in this sandbox (see GAP above); artifacts complete.
- `tools/cicids/` and `tools/pilot/` are empty placeholder dirs (untracked by git).
- Replay MTTD uses VirtualClock injection; wall-clock metrics require live capture (M7+ ops scope).
