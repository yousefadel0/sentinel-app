"""LLM model benchmark — same labeled cases through N endpoints.

Each candidate is an ``LLMClient`` (endpoint resolved from its own env var),
so comparing models means pointing different env vars at different
endpoints. Every call goes through the production ``triage_incident`` path,
so what is measured is exactly what would run in the appliance: schema
validity under the strict §5a parser, agreement with the labeled attack
type, whether the recommended action is at least as cautious as the playbook
allows, and latency. Cost is reported only when a per-call price is given.
"""
from __future__ import annotations

import statistics
from dataclasses import dataclass
from typing import Any, Mapping, Sequence

from sentinel.brain.audit import InMemoryPairSink
from sentinel.brain.client import LLMClient
from sentinel.brain.output import AGGRESSIVE_ACTIONS
from sentinel.brain.triage import triage_incident

#: Actions a model may recommend for a family without being MORE aggressive
#: than the v1 playbook (Project.md §6). Scans/DNS tunneling never warrant
#: an automatic block, and DDoS must not be blind-blocked locally.
_MAX_ACTION: dict[str, frozenset[str]] = {
    "scan": frozenset({"notify_only", "escalate_human", "throttle_src"}),
    "dns_tunneling": frozenset({"notify_only", "escalate_human"}),
    "ddos_volumetric": frozenset({"notify_only", "escalate_human"}),
    "brute_force": frozenset({"notify_only", "escalate_human", "throttle_src",
                              "block_ip_temp"}),
    "c2_beacon": frozenset({"notify_only", "escalate_human",
                            "quarantine_asset", "block_ip_temp"}),
}


@dataclass(frozen=True)
class BenchCase:
    case_id: str
    alerts: Sequence[Any]
    expected_attack_type: str


def _pct(values: list[float], q: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    return ordered[min(len(ordered) - 1, int(q * len(ordered)))]


def run_benchmark(models: Mapping[str, LLMClient],
                  cases: Sequence[BenchCase], *,
                  price_per_call_usd: Mapping[str, float] | None = None
                  ) -> dict[str, dict[str, Any]]:
    out: dict[str, dict[str, Any]] = {}
    for name, client in models.items():
        sink = InMemoryPairSink()
        ok = correct = cautious = 0
        for case in cases:
            result, _ = triage_incident(case.case_id, list(case.alerts),
                                        client, sink=sink)
            if result is None:
                continue
            ok += 1
            correct += result.attack_type == case.expected_attack_type
            cautious += (result.recommended_action in
                         _MAX_ACTION[case.expected_attack_type])
        lat = [float(p.elapsed_ms) for p in sink.pairs if p.status == "ok"]
        n = len(cases)
        row: dict[str, Any] = {
            "cases": n,
            "valid_rate": round(ok / n, 3) if n else None,
            "type_accuracy": round(correct / n, 3) if n else None,
            "playbook_safe_rate": round(cautious / n, 3) if n else None,
            "latency_ms_p50": statistics.median(lat) if lat else None,
            "latency_ms_p95": _pct(lat, 0.95),
            "failures": {s: sum(1 for p in sink.pairs if p.status == s)
                         for s in sorted({p.status for p in sink.pairs
                                          if p.status != "ok"})},
        }
        if price_per_call_usd and name in price_per_call_usd:
            row["est_cost_usd"] = round(price_per_call_usd[name] * n, 4)
        out[name] = row
    return out


def default_cases() -> list[BenchCase]:
    """One labeled case per v1 family, built from the evaluation scenarios."""
    import random

    from sentinel.evaluation import harness as H

    rng = random.Random("bench")
    gens = {"scan": H.scan, "brute_force": H.brute, "ddos_volumetric": H.ddos,
            "c2_beacon": H.beacon, "dns_tunneling": H.dns_tunnel}
    cases = []
    for family, gen in gens.items():
        out = H.run_scenario(gen(rng))
        if out:
            cases.append(BenchCase(f"bench-{family}", [out[-1]], family))
    return cases


__all__ = ["BenchCase", "run_benchmark", "default_cases", "AGGRESSIVE_ACTIONS"]
