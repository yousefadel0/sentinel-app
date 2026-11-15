"""Playbooks-as-code for the five v1 attack types (§6 PLAYBOOKS v1).

Every recommendation carries an explicit 'because' rationale string (P6).
Dry-run parity: nothing here touches a network — it only names what WOULD
happen and why.
"""
from __future__ import annotations

from sentinel.decision.models import AttackType, Recommendation

# §6 verbatim behaviors. TTLs respect G3 (≤60). DDoS never blind-blocks
# distributed sources locally — upstream mitigation is recommended instead
# (Q7 enum value pinned by operator: recommend_upstream_mitigation).
PLAYBOOKS: dict[str, tuple[str, dict, str]] = {
    AttackType.SCAN.value: (
        "notify_only",
        {},
        "scan is low-severity recon; notify SOC, throttle only at autonomy L>=2",
    ),
    AttackType.BRUTE_FORCE.value: (
        "block_ip_temp",
        {"target": "src", "ttl_minutes": 30},
        "credential stuffing observed on wire; temporary source block for 30m",
    ),
    AttackType.DDOS_VOLUMETRIC.value: (
        "recommend_upstream_mitigation",
        {},
        "upstream call via SOAR; never blind-block distributed sources locally",
    ),
    AttackType.C2_BEACON.value: (
        "quarantine_asset",
        {"target": "dst", "ttl_minutes": 60},
        "periodic beaconing to C2; quarantine asset 60m with priority notify",
    ),
    AttackType.DNS_TUNNELING.value: (
        "notify_only",
        {"proposed_egress_rule": True},
        "dns tunneling suspected; notify plus proposed egress rule for human approval",
    ),
    AttackType.BASELINE_ANOMALY.value: (
        "notify_only", {},
        "new traffic pattern against the persisted local baseline; review evidence",
    ),
}


def recommend(attack_type: AttackType) -> Recommendation:
    """Table lookup — the ONLY path from attack type to action (binding 1)."""
    try:
        action, params, because = PLAYBOOKS[attack_type.value]
    except KeyError as exc:  # pragma: no cover - enum exhaustiveness guard
        raise ValueError(f"no playbook for {attack_type}") from exc
    return Recommendation(action=action, params=dict(params), because=because)
