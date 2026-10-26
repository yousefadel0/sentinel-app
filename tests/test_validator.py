"""M4 — Validator module tests (G6 single gate, strictness, TTL ceiling)."""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import pytest  # noqa: E402

from sentinel.decision.chain import CHAIN_ROWS, Phase  # noqa: E402
from sentinel.models import Action, ActionType  # noqa: E402
from sentinel.validator import (  # noqa: E402
    MAX_TTL_MINUTES,
    ValidationError,
    ValidationVerdict,
    Validator,
)
from tests.fixtures.decision.helpers import config_view  # noqa: E402


def block(ttl=30, target="203.0.113.9"):
    return Action(type=ActionType.BLOCK_IP_TEMP, target_ip=target,
                  ttl_minutes=ttl, rationale="test")


# --------------------------------------------------------------------- #
def test_single_source_rows_reexported_unchanged():
    """Binding 1: validator re-exports THE SAME six rows, phases intact."""
    v = Validator(config_view())
    assert v.rows is CHAIN_ROWS
    names = [r.name for r in CHAIN_ROWS]
    assert names == ["nat_fallback", "vlan_blind_spot", "liveness",
                     "critical_assets", "rate_limit", "asymmetric"]
    pre = {r.name for r in CHAIN_ROWS if r.phase is Phase.PRE_BAND}
    post = {r.name for r in CHAIN_ROWS if r.phase is Phase.POST_BAND}
    assert pre == {"nat_fallback", "vlan_blind_spot"}
    assert post == {"liveness", "critical_assets", "rate_limit", "asymmetric"}


def test_unknown_action_string_rejected_before_execution():
    """Binding 5: unknown strings die at the gate — nothing executes."""
    v = Validator(config_view())
    with pytest.raises(ValidationError, match="unknown action string"):
        v.validate(Action(type="block_everything_forever"))
    # and a non-str/non-enum type too
    with pytest.raises(ValidationError, match="unknown action type"):
        v.validate(Action(type=12345))


def test_ttl_over_ceiling_raises_at_gate():
    with pytest.raises(ValidationError, match="G3 ceiling"):
        v = Validator(config_view())
        v.validate(block(ttl=61))
    assert MAX_TTL_MINUTES == 60


def test_approved_happy_path_aggressive():
    v = Validator(config_view())
    assert v.validate(block()) is ValidationVerdict.APPROVED


def test_rejection_liveness_stale():
    v = Validator(config_view())
    got = v.validate(block(), facts={"liveness": "stale"})
    assert got is ValidationVerdict.REJECTED


def test_rejection_critical_asset_allowlist():
    v = Validator(config_view(critical_assets=frozenset({"203.0.113.9"})))
    got = v.validate(block(target="203.0.113.9"))
    assert got is ValidationVerdict.REJECTED


def test_rejection_rate_limit_breach():
    v = Validator(config_view())
    got = v.validate(block(), facts={"rate_limit_breach": True})
    assert got is ValidationVerdict.REJECTED


def test_rejection_asymmetric_downgrades_block_only():
    v = Validator(config_view(asymmetric_risk="high"))
    assert v.validate(block()) is ValidationVerdict.REJECTED
    thr = Action(type=ActionType.THROTTLE_SRC, target_ip="203.0.113.9",
                 ttl_minutes=30)
    assert v.validate(thr) is ValidationVerdict.APPROVED  # downgrade not reject


def test_non_aggressive_actions_need_no_chain_walk():
    v = Validator(config_view())
    a = Action(type=ActionType.NOTIFY_ONLY)
    assert v.validate(a, facts={"liveness": "stale"}) \
        is ValidationVerdict.APPROVED


def test_row_count_guard():
    with pytest.raises(ValidationError, match="exactly 6"):
        Validator(config_view(),
                  rows=tuple(list(CHAIN_ROWS)[:5]))


# --------------------------------------------------------------------- #
class _SpyActuator:
    name = "spy"

    def __init__(self):
        self.executed = []

    def execute(self, action):
        self.executed.append(action)
        from sentinel.models import ActionResult
        return ActionResult(ok=True, actuator=self.name)

    def rollback(self, token):
        from sentinel.models import ActionResult
        return ActionResult(ok=True, actuator=self.name)


def test_g6_guard_blocks_execution_on_rejection():
    """No code path reaches the actuator without passing the validator."""
    v = Validator(config_view(critical_assets=frozenset({"203.0.113.9"})))
    spy = _SpyActuator()
    guarded = v.guard(spy)
    with pytest.raises(ValidationError, match="G6"):
        guarded.execute(block(target="203.0.113.9"))
    assert spy.executed == []          # NEVER reached hardware


def test_g6_guard_passes_approved_action_through():
    v = Validator(config_view())
    spy = _SpyActuator()
    guarded = v.guard(spy)
    got = guarded.execute(block())
    assert got.ok is True and spy.executed and len(spy.executed) == 1
