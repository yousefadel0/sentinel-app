"""Triage orchestrator — the bounded LLM role, end to end.

Flow per incident:
  1. build_safe_input()  — whitelist projection (the ONLY outbound shape)
  2. render_prompt()     — verbatim prompt string
  3. client.complete()   — bounded transport call
  4. parse_output()      — JSON-schema-only validation
  5. audit pair VERBATIM — every outcome audited, including failures
  6. return TriageResult | None

P4 silent degradation: ANY exception (transport, timeout, schema) ⇒ return
None; the rule-based path continues with NO error leak into SOC output.
The caller feeds a non-None result's severity into DecisionEngine.evaluate
(severity_override seam) — banding, tier caps and the §3.1 chain still fully
apply, so the LLM can never bypass the deterministic engine.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Sequence

from sentinel.brain.audit import InMemoryPairSink, PairSink, PromptResponsePair
from sentinel.brain.client import LLMClient
from sentinel.brain.output import BrainOutputError, TriageResult, parse_output
from sentinel.brain.schema import SafeInput, build_safe_input, render_prompt


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def triage_incident(
    case_id: str,
    alerts: Sequence[Any],
    client: LLMClient,
    *,
    sink: PairSink | None = None,
    direction: str | None = None,
    geolocation: str | None = None,
    asn: int | None = None,
    baseline_deviation_sigma: float | None = None,
    first_seen: str | None = None,
) -> tuple[TriageResult | None, SafeInput]:
    """Run one bounded LLM triage; NEVER raises (P4).

    Returns (result, safe_input): result is None on any failure — endpoint
    unset, transport error, timeout, or schema violation. The SafeInput is
    always returned so callers/auditors can see exactly what WOULD have been
    sent. Every attempt audits its verbatim pair.
    """
    store = sink if sink is not None else InMemoryPairSink()
    safe_input = build_safe_input(
        case_id, alerts,
        direction=direction,
        geolocation=geolocation,
        asn=asn,
        baseline_deviation_sigma=baseline_deviation_sigma,
        first_seen=first_seen,
    )
    prompt_verbatim = render_prompt(safe_input)

    try:
        response = client.complete(prompt_verbatim)
    except Exception as exc:  # noqa: BLE001 — P4: swallow ALL, audit, fall back
        _audit(store, case_id, prompt_verbatim, "", "transport_error", -1,
               client, extra=(("error_class", type(exc).__name__),))
        return None, safe_input

    body = response.body
    try:
        result = parse_output(body)
    except BrainOutputError:
        _audit(store, case_id, prompt_verbatim, body, "parse_error",
               response.elapsed_ms, client)
        return None, safe_input

    _audit(store, case_id, prompt_verbatim, body, "ok",
           response.elapsed_ms, client)
    return result, safe_input


def _audit(store: PairSink, case_id: str, prompt: str, response: str,
           status: str, elapsed_ms: int, client: LLMClient,
           extra: tuple[tuple[str, str], ...] = ()) -> None:
    pair = PromptResponsePair(
        case_id=case_id,
        prompt_verbatim=prompt,
        response_verbatim=response,
        status=status,
        elapsed_ms=elapsed_ms,
        endpoint_env_var=client._env_var,
        temperature=client.temperature,
        ts=_utc_now_iso(),
        extra=extra,
    )
    store.append_pair(pair)
