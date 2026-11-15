"""Table-driven scoring arithmetic (§6). No hidden heuristics — every
constant is a named module-level value with its rationale documented.

D1: adjusted_score = clamp(base + additive §3.1 penalties, 0.0, 1.0);
penalties apply BEFORE banding. The FINAL clamped value is compared
against thresholds/bands.
"""
from __future__ import annotations

# Asset criticality weights (Q1-approved starting map). Protective bias:
# worst-case asset in the story drives priority (P5).
CRITICALITY_WEIGHTS: dict[str, float] = {
    "critical": 1.0,
    "high": 0.85,
    "medium": 0.65,
    "low": 0.45,
}

# Rule-derived severity per attack type (Q2-accepted defaults). Phase-2 SIEM
# enrichment may carry real severity later — the explicit override input on
# the engine is the seam for that; these defaults keep M3 deterministic.
SEVERITY_DEFAULTS: dict[str, int] = {
    "scan": 2,
    "brute_force": 4,
    "ddos_volumetric": 5,
    "c2_beacon": 4,
    "dns_tunneling": 3,
    "baseline_anomaly": 5,
}

# §3.1 additive penalties (verbatim magnitudes).
PENALTY_NAT_FALLBACK = -0.15      # step 1c: likely NAT gateway as src
PENALTY_BLIND_SPOT_VLAN = -0.20   # step 3: alert.vlan not monitored


def base_score(confidence: float, criticality: str, severity: int) -> float:
    """base = conf × crit_weight × (sev/5), clamped to [0,1].

    Raises KeyError/ValueError on unknown criticality or out-of-range inputs —
    callers feed validated config-view values only.
    """
    if not 0.0 <= confidence <= 1.0:
        raise ValueError(f"confidence must be in [0,1], got {confidence}")
    if not 1 <= severity <= 5:
        raise ValueError(f"severity must be in [1,5], got {severity}")
    weight = CRITICALITY_WEIGHTS[criticality]
    return round(min(1.0, max(0.0, confidence * weight * (severity / 5))), 6)


def apply_penalties(base: float, deltas: list[float]) -> float:
    """Additive §3.1 penalties, then clamp — the ONLY score mutation point."""
    adjusted = base + sum(deltas)
    return round(min(1.0, max(0.0, adjusted)), 6)


def band(score: float) -> str:
    """§6 global bands from the FINAL clamped score (D1)."""
    if score >= 0.90:
        return "auto"
    if score >= 0.70:
        return "human"
    return "log_only"
