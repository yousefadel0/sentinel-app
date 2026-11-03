"""Decision-layer value types (§5 ALLOWED_ACTIONS, §6 outcomes).

Every Decision carries cap_applied + the FULL audit_events list — including
log-only ones — so any decision is reconstructable years later (P6).
"""
from __future__ import annotations

import enum
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any

APPROVAL_WINDOW_S = 900  # §6: human approval times out after 15 minutes


class Outcome(str, enum.Enum):
    """Banded/chained verdicts. In dry-run every outcome is a recommendation."""

    AUTO_ACT = "auto_act"
    AUTO_THROTTLE = "auto_throttle"
    HUMAN_APPROVAL = "human_approval"
    ESCALATE_HUMAN = "escalate_human"
    NOTIFY_ONLY = "notify_only"
    LOG_ONLY = "log_only"


class AttackType(str, enum.Enum):
    """The five v1 attack types (§2 IN-list) — playbook table keys."""

    SCAN = "scan"
    BRUTE_FORCE = "brute_force"
    DDOS_VOLUMETRIC = "ddos_volumetric"
    C2_BEACON = "c2_beacon"
    DNS_TUNNELING = "dns_tunneling"


# Signal families (M1 vocabulary) -> attack type. Priority order matters:
# more specific families win when an incident mixes signals.
SIGNAL_TO_ATTACK: tuple[tuple[str, AttackType], ...] = (
    ("auth_fail_burst", AttackType.BRUTE_FORCE),
    ("beacon_periodic", AttackType.C2_BEACON),
    ("dns_tunneling", AttackType.DNS_TUNNELING),
    ("volume_spike", AttackType.DDOS_VOLUMETRIC),
    ("ddos_volumetric", AttackType.DDOS_VOLUMETRIC),
    ("scan", AttackType.SCAN),
)


@dataclass(frozen=True)
class AuditEvent:
    """One named step of the decision path (P6). Names are glossary-controlled."""

    name: str
    detail: str = ""


@dataclass(frozen=True)
class Recommendation:
    """Playbook output: what we WOULD do and why (dry-run parity, P5)."""

    action: str                 # ActionType value string (§5 enum verbatim)
    params: dict[str, Any] = field(default_factory=dict)
    because: str = ""


@dataclass(frozen=True)
class Decision:
    """Full verdict for one incident — the unit SOC reviews (and audits)."""

    incident_id: str
    outcome: Outcome
    base_score: float                     # conf × crit × sev, pre-penalty
    score: float                          # clamped adjusted score (D1)
    tier: str                             # A | B | C
    cap_applied: str | None               # which cap/downgrade engaged, if any
    audit_events: tuple[AuditEvent, ...]  # COMPLETE path, P6
    recommendation: Recommendation | None
    approval_deadline: datetime | None = None   # set iff HUMAN_APPROVAL (= now+900s)
    would: str = ""                       # "would do X because Y" phrase
    inputs: dict = field(default_factory=dict)  # score inputs, for explanation

    def __post_init__(self) -> None:
        if not 0.0 <= self.score <= 1.0 or not 0.0 <= self.base_score <= 1.0:
            raise ValueError("scores must be within [0,1]")
