"""§3.1 pre-action validator as ONE ordered table of named rows.

Architectural correction (operator-approved): each step is a SINGLE row with
an explicit phase —
  pre_band  : touches ONLY the score (+ emits its audit event once);
              applied inside scoring.apply_penalties before banding.
  post_band : modifies ONLY action/outcome; NEVER touches the score.
Each row is evaluated exactly once per decision, so double-apply is
structurally impossible (test pins: one blind-spot alert ⇒ exactly one
"alert_from_blind_spot_vlan" event and one −0.20 total).

The engine NEVER invents facts: nat_resolved_src/liveness are injected;
absence is a fact pattern, not a guess (Q4).
"""
from __future__ import annotations

import enum
from dataclasses import dataclass

from sentinel.decision.scoring import (
    PENALTY_BLIND_SPOT_VLAN,
    PENALTY_NAT_FALLBACK,
)


class Phase(str, enum.Enum):
    PRE_BAND = "pre_band"
    POST_BAND = "post_band"


@dataclass(frozen=True)
class ChainRow:
    """One §3.1 step: name, phase, effect, verbatim audit name."""

    name: str
    phase: Phase
    audit_name: str                    # glossary-controlled, emitted at most once
    penalty_delta: float | None = None # pre_band rows only
    outcome_override: str | None = None  # post_band effect (Outcome value)
    detail: str = ""


# Ordered §3.1 table — the enumerable decision surface (binding 1).
CHAIN_ROWS: tuple[ChainRow, ...] = (
    ChainRow("nat_fallback", Phase.PRE_BAND, "nat_fallback_penalty",
             penalty_delta=PENALTY_NAT_FALLBACK,
             detail="src private AND outside local subnets; no live binding"),
    ChainRow("vlan_blind_spot", Phase.PRE_BAND, "alert_from_blind_spot_vlan",
             penalty_delta=PENALTY_BLIND_SPOT_VLAN,
             outcome_override="escalate_human",  # §3.1 step 3: BOTH effects,
             detail="alert.vlan not in monitored_vlans"),
    ChainRow("liveness", Phase.POST_BAND, "stale_session_drift",
             outcome_override="log_only",
             detail="target flow not alive per zeek conn state"),
    ChainRow("critical_assets", Phase.POST_BAND, "critical_asset_allowlist_hit",
             outcome_override="escalate_human",
             detail="G1: allowlisted target + aggressive action; NO exceptions"),
    ChainRow("rate_limit", Phase.POST_BAND, "rate_limit_breach_alarm",
             outcome_override="notify_only",
             detail="G4: block budget exhausted; fallback + internal alarm"),
    ChainRow("asymmetric", Phase.POST_BAND, "asymmetric_routing_risk",
             outcome_override=None,  # action-level downgrade block->throttle
             detail="placement.asymmetric_risk == high"),
)


@dataclass(frozen=True)
class Facts:
    """Injected §3.1 facts for one evaluation (engine never invents these).

    vlan_monitored is tri-state: None (default) means DERIVE it from the
    member alerts' vlan fields vs config monitored_vlans — a derivation from
    real data, not an invented fact; an explicit bool forces the predicate
    for targeted tests.
    """

    nat_resolved_src: str | None = None   # live binding result, if any
    liveness: str = "unknown"             # alive | stale | unknown
    vlan_monitored: bool | None = None    # None -> derive from alerts+config
    src_private_outside_local: bool = False  # NAT step-1c predicate, precomputed


@dataclass(frozen=True)
class RowResult:
    """What one row decided this pass — exactly one result per row."""

    row: str
    fired: bool
    audit_name: str | None = None
    penalty_delta: float = 0.0
    outcome_override: str | None = None
    action_downgrade: str | None = None   # e.g. block_ip_temp -> throttle_src
    detail: str = ""
