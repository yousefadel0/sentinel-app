"""§3.1 chain table: order, single-row phases, no double-apply.

The architectural correction is pinned here: each step is ONE row with an
explicit phase; pre_band rows touch only the score, post_band rows only the
outcome/action — and every fired row emits its audit event exactly once.
"""
from __future__ import annotations

import pytest

from sentinel.decision.chain import CHAIN_ROWS, Facts, Phase
from sentinel.decision.engine import AGGRESSIVE_ACTIONS, ConfigView, DecisionEngine
from sentinel.models import ConfidenceTier
from sentinel.decision.models import Outcome
from tests.fixtures.decision.helpers import alert, config_view, engine


def _names(decision):
    return [e.name for e in decision.audit_events]


# --------------------------------------------------------------------- #
# table shape (binding 1: enumerable named rows)
# --------------------------------------------------------------------- #
def test_chain_table_rows_and_phases_exact():
    assert [(r.name, r.phase.value) for r in CHAIN_ROWS] == [
        ("nat_fallback", "pre_band"),
        ("vlan_blind_spot", "pre_band"),
        ("liveness", "post_band"),
        ("critical_assets", "post_band"),
        ("rate_limit", "post_band"),
        ("asymmetric", "post_band"),
    ]


def test_pre_band_rows_carry_penalties_post_band_do_not():
    for row in CHAIN_ROWS:
        if row.phase is Phase.PRE_BAND:
            assert row.penalty_delta is not None
        else:
            assert row.penalty_delta is None


# --------------------------------------------------------------------- #
# each step fires alone with its verbatim audit name
# --------------------------------------------------------------------- #
def test_nat_fallback_needs_both_predicates_true():
    eng, _ = engine()
    inc = lambda: None
    from tests.fixtures.decision.helpers import IncidentStub
    a = alert("auth_fail_burst", 0.95, crit="critical")
    # private src outside local subnets + NO live binding -> fires
    d = eng.evaluate(IncidentStub([a]),
                     Facts(nat_resolved_src=None,
                           src_private_outside_local=True))
    assert "nat_fallback_penalty" in _names(d)
    assert d.score == pytest.approx(d.base_score - 0.15)


def test_nat_fallback_negative_controls():
    eng, _ = engine()
    from tests.fixtures.decision.helpers import IncidentStub
    a = alert("auth_fail_burst", 0.95, crit="critical")
    # live NAT binding exists -> no fallback
    d1 = eng.evaluate(IncidentStub([a]),
                      Facts(nat_resolved_src="203.0.113.7",
                            src_private_outside_local=True))
    assert "nat_fallback_penalty" not in _names(d1)
    assert d1.score == pytest.approx(d1.base_score)
    # public src (not private+outside-local) -> no fallback even w/o binding
    d2 = eng.evaluate(IncidentStub([a]),
                      Facts(nat_resolved_src=None,
                            src_private_outside_local=False))
    assert "nat_fallback_penalty" not in _names(d2)


def test_liveness_stale_uses_verbatim_name_and_downgrades():
    eng, _ = engine()
    from tests.fixtures.decision.helpers import IncidentStub
    a = alert("volume_spike", 1.0, crit="critical")   # auto band otherwise
    d = eng.evaluate(IncidentStub([a]), Facts(liveness="stale"))
    assert d.outcome is Outcome.LOG_ONLY
    assert "stale_session_drift" in _names(d)
    assert "liveness_unknown_treated_stale" not in _names(d)


def test_liveness_unknown_escalates_instead_of_silencing():
    """No flow proof must never silence an incident: an auto outcome becomes
    a human escalation (the executor still refuses to act without proof)."""
    eng, _ = engine()
    from tests.fixtures.decision.helpers import IncidentStub
    a = alert("volume_spike", 1.0, crit="critical")
    d = eng.evaluate(IncidentStub([a]), Facts(liveness="unknown"))
    assert d.outcome is Outcome.ESCALATE_HUMAN
    assert "liveness_unverified" in _names(d)
    assert "stale_session_drift" not in _names(d)


def test_liveness_stale_is_logged_only():
    eng, _ = engine()
    from tests.fixtures.decision.helpers import IncidentStub
    a = alert("volume_spike", 1.0, crit="critical")
    d = eng.evaluate(IncidentStub([a]), Facts(liveness="stale"))
    assert d.outcome is Outcome.LOG_ONLY
    assert "stale_session_drift" in _names(d)


def test_blind_spot_vlan_single_event_single_penalty():
    """No-double-apply pin (operator correction): exactly ONE event and one
    −0.20 total for a blind-spot alert."""
    eng, _ = engine()
    from tests.fixtures.decision.helpers import IncidentStub
    a = alert("scan", 0.99, crit="critical", vlan="legacy_lab")
    d = eng.evaluate(IncidentStub([a]))
    names = _names(d)
    assert names.count("alert_from_blind_spot_vlan") == 1
    assert d.score == pytest.approx(max(0.0, d.base_score - 0.20))
    assert d.outcome is Outcome.ESCALATE_HUMAN   # §3.1 step 3 effect


# --------------------------------------------------------------------- #
# order matters: first firing override wins; later rows still emit events
# --------------------------------------------------------------------- #
def test_order_liveness_beats_g1_but_both_events_present():
    eng, _ = engine(config_view(critical_assets=frozenset({"10.0.0.99"})))
    from tests.fixtures.decision.helpers import IncidentStub
    a = alert("auth_fail_burst", 0.95, crit="critical", dst="10.0.0.99")
    d = eng.evaluate(IncidentStub([a], dst_ip="10.0.0.99"),
                     Facts(liveness="stale"))
    assert d.outcome is Outcome.LOG_ONLY          # liveness (step 2) fires first
    names = _names(d)
    assert "stale_session_drift" in names
    assert "critical_asset_allowlist_hit" in names   # P6: full path recorded


def test_all_pass_yields_untouched_verdict():
    eng, _ = engine()
    from tests.fixtures.decision.helpers import IncidentStub
    a = alert("volume_spike", 1.0, crit="critical")
    d = eng.evaluate(IncidentStub([a]), Facts(liveness="alive"))
    assert d.outcome is Outcome.AUTO_ACT
    assert d.cap_applied is None
    assert _names(d) == []                        # no chain events fired


def test_aggressive_set_is_the_g1_surface():
    assert AGGRESSIVE_ACTIONS == frozenset({"block_ip_temp",
                                            "quarantine_asset"})
