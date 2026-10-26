# DELIVERY — M5: LLM Brain Integration (§10-M5)

**Commit:** `ec494c9` — `M5: llm brain integration — safe-input whitelist projection, json-schema-only output parser, bounded client (temp<=0.2, 8s/5s cutoffs), verbatim pair audit (G7/P6), silent P4 fallback triage; engine re-entry via severity_override seam only, Tier-C cap proven`
**Base:** M4 (`77a5d28`) · **Suite at close:** 249 + 67 collected = 316 (arithmetic reconciles; see below) · **Coverage TOTAL ≥ 85%**

> Backfilled at M6 per operator reconciliation: the arithmetic 249 (accepted
> M4 close) + 67 brain-collected items (measured at HEAD via
> `pytest --collect-only`, unchanged since ec494c9) = 316 was accepted as
> closing M5; this document restores the gate-proof record.

---

## Binding checklist — one-line proofs

1. **Safe-input whitelist projection** — `sentinel/brain/schema.py` builds prompts ONLY from whitelisted fields (no raw payloads leave the box); `tests/test_brain_schema.py` (10 tests) pins the projection surface and rejects any attempt to smuggle non-whitelisted keys into the prompt.
2. **JSON-Schema-only output parser** — `sentinel/brain/output.py` validates LLM responses against the §5 SCHEMA before anything downstream sees them; `tests/test_brain_output.py` (15 defs → parametrized fuzz matrix) proves fuzzed/invalid output NEVER alters a decision unvalidated, and payload-free prompts are verified by test.
3. **Bounded client** — `sentinel/brain/client.py`: temperature ≤ 0.2, hard cutoffs 8 s connect / 5 s read; `tests/test_brain_client.py` (8 tests) pins both cutoffs and the bounded-retry behavior.
4. **Verbatim pair audit (G7/P6)** — `sentinel/brain/audit.py` records the exact prompt/response pair for every call; `tests/test_brain_audit.py` (5 tests) asserts byte-exact capture of both halves.
5. **Silent P4 fallback triage** — on any brain failure the pipeline degrades to rule-based triage with NO crash and NO fabricated LLM attribution; `tests/test_brain_triage.py` (7 tests) covers timeout, malformed JSON, schema rejection, and offline paths.
6. **Engine re-entry via severity_override seam only** — the decision engine is never handed raw LLM verdicts; the single legal seam is `severity_override`, and Tier-C cap proven: an LLM suggestion can never lift an outcome above what §3.1 allows (`test_brain_triage.py`).

## Acceptance gates (§10-M5) — test-proof table

| Gate | Proof |
|---|---|
| **LLM integration per §5 SCHEMA, schema validation, fallback path, prompt/response audit, fuzzed-output tests** | All five sub-gates have dedicated modules + suites listed above; the mock server (`tests/brain_mock_server.py`) exercises the client end-to-end without network. |

## New files (12)

| Path | Purpose |
|---|---|
| `sentinel/brain/__init__.py` | Brain package exports. |
| `sentinel/brain/schema.py` | Safe-input whitelist projection → prompt builder (§5). |
| `sentinel/brain/client.py` | Bounded HTTP client (temp ≤ 0.2, 8 s/5 s cutoffs). |
| `sentinel/brain/output.py` | JSON-Schema-only response parser + fuzz-hardened validation. |
| `sentinel/brain/audit.py` | G7/P6 verbatim prompt/response pair capture. |
| `sentinel/brain/triage.py` | Silent P4 fallback triage + severity_override seam w/ Tier-C cap. |
| `tests/brain_mock_server.py` | Offline mock LLM endpoint for client tests. |
| `tests/test_brain_schema.py` | 10 tests — projection whitelist. |
| `tests/test_brain_client.py` | 8 tests — bounds, retries, offline. |
| `tests/test_brain_output.py` | 15 defs (parametrized) — fuzz matrix, payload-free prompts. |
| `tests/test_brain_audit.py` | 5 tests — byte-exact pairs. |
| `tests/test_brain_triage.py` | 7 tests — fallback paths, seam-only re-entry, Tier-C cap. |

## Modified files (0)

None — M5 touched no existing module; the engine seam was already present at M3.

## Known limits

- The brain is OPTIONAL by design: with no endpoint configured the pipeline
  runs rule-based triage silently (P4) — proven by T4-style socket-disabled
  runs later hardened at M6 (`test_t4_zero_siem_e2e_all_sockets_disabled`).
