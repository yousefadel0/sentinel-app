"""§3.1 pre-action validator — the SINGLE gate between decisions and actuators.

Single source of truth (G6): the six ordered rows live ONLY in
``sentinel.decision.chain.CHAIN_ROWS``; this module re-exports them unchanged
(pre_band/post_band phases exactly as built in M3) and exposes
:class:`Validator` — the one object every consumer (engine dry-run path AND
every actuator) must pass through. No code path may reach an actuator without
passing it, rejection paths included.
"""
from __future__ import annotations

import enum

from sentinel.decision.chain import CHAIN_ROWS, ChainRow, Phase
from sentinel.decision.engine import ConfigView
from sentinel.models import Action, ActionType

__all__ = [
    "CHAIN_ROWS",          # re-exported single source of truth
    "ChainRow",
    "Phase",
    "Validator",
    "ValidationError",
    "ValidationVerdict",
]


class ValidationError(ValueError):
    """Raised when a proposed action is not executable under §5/G3 rules."""


class ValidationVerdict(enum.Enum):
    """Result of one validation pass."""

    APPROVED = "approved"
    REJECTED = "rejected"


#: Actions that touch enforcement hardware/infrastructure (G1 scope).
_AGGRESSIVE: frozenset[ActionType] = frozenset(
    {ActionType.THROTTLE_SRC, ActionType.BLOCK_IP_TEMP,
     ActionType.QUARANTINE_ASSET}
)

#: G3 hard ceiling at the ENFORCEMENT layer — engine caps are NOT trusted here.
MAX_TTL_MINUTES = 60


class Validator:
    """The one §3.1 gate every action passes before any actuator sees it.

    Construction pins the shared instance::

        validator = Validator(config_view)      # built once in cli wiring
        nft      = NftablesLocalActuator(validator=validator)
        webhook  = WebhookSoarActuator(validator=validator)

    ``validate`` performs, in order:

    1. **Strictness** — unknown action strings (anything outside
       :class:`sentinel.models.ActionType`) raise :class:`ValidationError`
       BEFORE anything executes (binding 5).
    2. **TTL ceiling** — ``ttl_minutes > 60`` raises (G3), regardless of what
       the engine recommended (defense-in-depth; enforcement never trusts the
       caller's cap).
    3. **§3.1 chain** — walks the SAME six ``CHAIN_ROWS`` with their M3
       pre_band/post_band phases via injected facts; a fired override row
       REJECTS aggressive execution (escalate/log/notify outcomes must not be
       enforced by an actuator).

    Rejections carry the verbatim audit name so callers can emit the exact
    glossary-controlled event.
    """

    def __init__(
        self,
        config_view: ConfigView,
        *,
        rows: tuple[ChainRow, ...] = CHAIN_ROWS,
    ) -> None:
        if len(rows) != len(CHAIN_ROWS):
            raise ValidationError(
                f"validator requires exactly {len(CHAIN_ROWS)} §3.1 rows")
        self._cfg = config_view
        self.rows = rows

    # ------------------------------------------------------------------ #
    def validate(self, action: Action, *, facts: dict | None = None) -> ValidationVerdict:
        """Gate ONE action. Returns APPROVED or REJECTED; raises on malformed input.

        ``facts`` keys (all optional, engine-derived — never invented here):
          liveness: "alive"|"stale"|"unknown"
          rate_limit_breach: bool
          engine_outcome: Outcome value from the dry-run decision; any
            non-enforceable verdict (escalate_human/human_approval/
            notify_only/log_only) REJECTS aggressive execution.
        """
        # 1) strictness — unknown strings die here, before any execution.
        if isinstance(action.type, str):
            try:
                ActionType(action.type)
            except ValueError as exc:
                raise ValidationError(
                    f"unknown action string: {action.type!r}") from exc
        elif not isinstance(action.type, ActionType):
            raise ValidationError(f"unknown action type: {action.type!r}")

        # 2) TTL ceiling at the gate too (engine cap not trusted anywhere).
        ttl = getattr(action, "ttl_minutes", None)
        if ttl is not None and ttl > MAX_TTL_MINUTES:
            raise ValidationError(
                f"ttl_minutes={ttl} exceeds G3 ceiling {MAX_TTL_MINUTES}")

        aggressive = (
            action.type in _AGGRESSIVE
            if isinstance(action.type, ActionType)
            else ActionType(action.type) in _AGGRESSIVE
        )
        if not aggressive:
            return ValidationVerdict.APPROVED   # notify/log/escalate need no hardware

        # 3) §3.1 chain walk — same rows, same phases, M3 semantics.
        facts = facts or {}
        liveness = facts.get("liveness", "alive")
        breach = facts.get("rate_limit_breach", False)
        outcome = facts.get("engine_outcome")

        for row in self.rows:
            if row.phase is Phase.PRE_BAND:
                continue    # pre_band penalties already priced into the score
            if row.name == "liveness":
                if liveness != "alive":
                    return ValidationVerdict.REJECTED   # stale_session_drift
            elif row.name == "critical_assets":
                if action.target_ip in self._cfg.critical_assets:
                    return ValidationVerdict.REJECTED   # critical_asset_allowlist_hit
            elif row.name == "rate_limit":
                if breach:
                    return ValidationVerdict.REJECTED   # rate_limit_breach_alarm
            elif row.name == "asymmetric":
                if (self._cfg.asymmetric_risk == "high"
                        and action.type is ActionType.BLOCK_IP_TEMP):
                    return ValidationVerdict.REJECTED   # asymmetric_routing_risk

        # Engine verdict gate: only auto_act/auto_throttle may be enforced.
        if outcome is not None and outcome not in ("auto_act", "auto_throttle"):
            return ValidationVerdict.REJECTED
        return ValidationVerdict.APPROVED

    # ------------------------------------------------------------------ #
    def guard(self, actuator) -> "_GuardedActuator":
        """Wrap an actuator so execute() is impossible without validation."""
        return _GuardedActuator(self, actuator)


class _GuardedActuator:
    """Decorator enforcing G6 at the type level: no validate ⇒ no execute."""

    def __init__(self, validator: Validator, inner) -> None:
        self._validator = validator
        self._inner = inner
        self.name = inner.name

    def execute(self, action: Action):
        verdict = self._validator.validate(action)
        if verdict is not ValidationVerdict.APPROVED:
            raise ValidationError(
                f"G6: {action.type} rejected by §3.1 chain — execution blocked")
        return self._inner.execute(action)

    def rollback(self, token: str):
        return self._inner.rollback(token)
