"""M4 — dry-run parity triple-agreement (binding 6).

engine recommendation == validator-approved action == actuator receipt,
or the test fails. The SAME shared Validator instance gates both paths
(single source of truth). Playbook names are the wire surface: only
enforcement playbooks (block_ip_temp, quarantine_asset) reach an actuator;
notify/recommend_* recs must never be executed.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from subprocess import CompletedProcess  # noqa: E402

from sentinel.models import Action, ActionType  # noqa: E402
from sentinel.decision.chain import Facts  # noqa: E402
from sentinel.actuators.nftables_local import NftablesLocalActuator  # noqa: E402
from sentinel.validator import ValidationVerdict, Validator  # noqa: E402
from tests.fixtures.decision.helpers import (  # noqa: E402
    IncidentStub,
    alert,
    config_view,
    engine as wired_engine,
)

# Playbook string -> enforcement ActionType. Non-enforcement playbooks
# (notify_only, recommend_upstream_mitigation) have NO entry on purpose:
# mapping them is a parity violation and dies loudly here.
_ENFORCEABLE = {
    "block_ip_temp": ActionType.BLOCK_IP_TEMP,
    "quarantine_asset": ActionType.QUARANTINE_ASSET,
}


def _rec_to_action(rec, dst_ip):
    """Wire Recommendation → Action with NO invention (parity seam)."""
    atype = _ENFORCEABLE.get(rec.action)
    if atype is None:
        raise ValueError(f"non-enforceable playbook {rec.action!r} "
                         "must never reach an actuator")
    ttl = int((rec.params or {}).get("ttl_minutes") or 30)
    return Action(type=atype, target_ip=dst_ip, ttl_minutes=ttl,
                  params=dict(rec.params or {}),
                  rationale=(rec.because or "parity"))


class Runner:
    def __init__(self):
        self.calls = []

    def __call__(self, cmd, **kw):
        self.calls.append(cmd)
        return CompletedProcess(cmd, 0, "", "")


def test_parity_auto_act_block_flow():
    """Tier-A brute force ⇒ engine rec == validator APPROVED == receipt."""
    eng, _ = wired_engine()
    inc = IncidentStub([alert("auth_fail_burst", 1.0, crit="critical")])
    dec = eng.evaluate(inc, Facts(liveness="alive"), severity_override=5)
    assert dec.outcome.value == "auto_act"
    assert dec.recommendation.action == "block_ip_temp"

    validator = Validator(config_view())
    action = _rec_to_action(dec.recommendation, inc.dst_ip)
    verdict = validator.validate(
        action, facts={"engine_outcome": dec.outcome.value})
    assert verdict is ValidationVerdict.APPROVED

    runner = Runner()
    nft = NftablesLocalActuator(validator, runner=runner,
                                which_fn=lambda _: "/usr/sbin/nft")
    got = nft.execute(action)
    # triple agreement: recommendation string == gated action == receipt ok
    assert (dec.recommendation.action
            == action.type.value
            == ActionType.BLOCK_IP_TEMP.value)
    assert got.ok is True and got.rollback_token
    assert got.actuator == "nftables_local"


def test_parity_escalate_never_reaches_actuator():
    """Blind-spot VLAN ⇒ engine escalates; validator REJECTS enforcement."""
    cfg = config_view(monitored_vlans=frozenset({"prod"}))
    eng, _ = wired_engine(cfg)
    off_vlan = alert("port_scan", 0.97, vlan="guest")   # unmonitored
    inc = IncidentStub([off_vlan])
    dec = eng.evaluate(inc, Facts(liveness="alive"))
    assert dec.outcome.value == "escalate_human"

    validator = Validator(cfg)
    action = Action(type=ActionType.BLOCK_IP_TEMP, target_ip=inc.dst_ip,
                    ttl_minutes=30)
    got = validator.validate(action, facts={"engine_outcome":
                                            dec.outcome.value})
    assert got is not ValidationVerdict.APPROVED


def test_parity_quarantine_receipt_matches_recommendation():
    """C2 beacon rec → same action at gate → nft rule carries the host."""
    eng, _ = wired_engine()
    inc = IncidentStub([alert("beacon_periodic", 1.0, crit="critical")])
    dec = eng.evaluate(inc, Facts(liveness="alive"), severity_override=5)
    assert dec.recommendation.action == "quarantine_asset"
    assert dec.recommendation.params["ttl_minutes"] == 60

    validator = Validator(config_view())
    action = _rec_to_action(dec.recommendation, inc.dst_ip)
    assert validator.validate(
        action, facts={"engine_outcome": dec.outcome.value}) \
        is ValidationVerdict.APPROVED
    assert action.ttl_minutes == 60          # playbook TTL carried verbatim

    runner = Runner()
    nft = NftablesLocalActuator(validator, runner=runner,
                                which_fn=lambda _: "/usr/sbin/nft")
    got = nft.execute(action)
    assert (dec.recommendation.action
            == action.type.value
            == ActionType.QUARANTINE_ASSET.value)
    assert got.ok is True
