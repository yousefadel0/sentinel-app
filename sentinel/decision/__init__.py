"""Sentinel decision engine (M3) — public surface.

Dry-run only in M3: every output is a "would do X because Y" package;
nothing here touches a network.
"""
from sentinel.decision.autonomy import AutonomyController
from sentinel.decision.chain import CHAIN_ROWS, ChainRow, Facts, Phase
from sentinel.decision.engine import AGGRESSIVE_ACTIONS, ConfigView, DecisionEngine
from sentinel.decision.models import (
    APPROVAL_WINDOW_S,
    AttackType,
    AuditEvent,
    Decision,
    Outcome,
    Recommendation,
)
from sentinel.decision.playbooks import PLAYBOOKS
from sentinel.decision.rate_limiter import RateLimiter
from sentinel.decision.scoring import (
    CRITICALITY_WEIGHTS,
    SEVERITY_DEFAULTS,
    band,
    base_score,
)

__all__ = [
    "AGGRESSIVE_ACTIONS",
    "APPROVAL_WINDOW_S",
    "AttackType",
    "AuditEvent",
    "AutonomyController",
    "CHAIN_ROWS",
    "ChainRow",
    "ConfigView",
    "CRITICALITY_WEIGHTS",
    "Decision",
    "DecisionEngine",
    "Facts",
    "Outcome",
    "Phase",
    "PLAYBOOKS",
    "RateLimiter",
    "Recommendation",
    "SEVERITY_DEFAULTS",
    "band",
    "base_score",
]
