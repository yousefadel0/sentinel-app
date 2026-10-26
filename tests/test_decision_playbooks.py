"""Playbooks-as-code ×5 (§6 v1): verbatim actions/params + 'because' strings."""
from __future__ import annotations

import pytest

from sentinel.decision.models import AttackType, Recommendation
from sentinel.decision.playbooks import PLAYBOOKS, recommend


def test_table_covers_exactly_five_attack_types():
    assert set(PLAYBOOKS) == {t.value for t in AttackType}


@pytest.mark.parametrize("attack,action,params", [
    (AttackType.SCAN, "notify_only", {}),
    (AttackType.BRUTE_FORCE, "block_ip_temp",
     {"target": "src", "ttl_minutes": 30}),
    (AttackType.DDOS_VOLUMETRIC, "recommend_upstream_mitigation", {}),
    (AttackType.C2_BEACON, "quarantine_asset",
     {"target": "dst", "ttl_minutes": 60}),
    (AttackType.DNS_TUNNELING, "notify_only", {"proposed_egress_rule": True}),
])
def test_verbatim_action_and_params(attack, action, params):
    rec = recommend(attack)
    assert rec.action == action
    assert rec.params == params


@pytest.mark.parametrize("attack", list(AttackType))
def test_every_recommendation_has_because_rationale(attack):
    rec = recommend(attack)
    assert isinstance(rec, Recommendation)
    assert rec.because.strip() != ""


def test_ddos_never_blind_blocks_locally():
    rec = recommend(AttackType.DDOS_VOLUMETRIC)
    assert rec.action == "recommend_upstream_mitigation"   # Q7 verbatim enum
    assert "never blind-block distributed sources locally" in rec.because


def test_ttls_respect_g3_ceiling():
    for _, (_, params, _) in PLAYBOOKS.items():
        ttl = params.get("ttl_minutes")
        if ttl is not None:
            assert 0 < ttl <= 60


def test_scan_throttles_only_at_l_ge_2_note_present():
    assert "L>=2" in recommend(AttackType.SCAN).because


def test_playbook_lookup_is_pure_table_no_heuristics():
    """Same input -> same output object values (determinism binding 1)."""
    r1, r2 = recommend(AttackType.C2_BEACON), recommend(AttackType.C2_BEACON)
    assert r1 == r2
