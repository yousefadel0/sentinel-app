"""Engine: bands, tier caps (D2 + clarification 1), G1 rejection matrix,
15-min approval timeout via injected clock, and the G4 rate limiter.
"""
from __future__ import annotations

import pytest

from sentinel.decision.chain import Facts
from sentinel.decision.engine import ConfigView, DecisionEngine
from sentinel.models import ConfidenceTier
from sentinel.decision.models import APPROVAL_WINDOW_S, Outcome
from sentinel.decision.rate_limiter import RateLimiter
from tests.fixtures.decision.helpers import (
    FakeClock,
    IncidentStub,
    alert,
    config_view,
    engine,
)


# --------------------------------------------------------------------- #
# global bands
# --------------------------------------------------------------------- #
def test_auto_band_full_confidence_ddos_vs_critical():
    eng, _ = engine()
    d = eng.evaluate(IncidentStub([alert("volume_spike", 1.0, crit="critical")]),
                     Facts(liveness="alive"))
    assert d.outcome is Outcome.AUTO_ACT
    assert d.score >= 0.90


def test_human_band_brute_force_93_vs_critical_sets_deadline_from_clock():
    clk = FakeClock()
    eng, _ = engine(clock=clk)
    d = eng.evaluate(IncidentStub([alert("auth_fail_burst", 0.93,
                                         crit="critical")]),
                     Facts(liveness="alive"))
    assert d.outcome is Outcome.HUMAN_APPROVAL
    assert 0.70 <= d.score < 0.90
    assert d.approval_deadline is not None
    assert (d.approval_deadline - clk()).total_seconds() == APPROVAL_WINDOW_S


def test_log_only_band_low_score_has_no_recommendation_but_full_audit():
    eng, _ = engine()
    d = eng.evaluate(IncidentStub([alert("scan", 0.30, crit="low")]),
                     Facts(liveness="alive"))
    assert d.outcome is Outcome.LOG_ONLY
    assert d.recommendation is None
    assert d.would.startswith("would log only because")
    assert d.cap_applied is None            # clarification 3: fields present


# --------------------------------------------------------------------- #
# tier caps — D2 precedence + clarification 1 semantics
# --------------------------------------------------------------------- #
def test_tier_c_caps_auto_act_at_notify_only_even_at_score_099():
    eng, _ = engine()
    a = alert("volume_spike", 0.99, tier=ConfidenceTier.C, crit="critical")
    d = eng.evaluate(IncidentStub([a]), Facts(liveness="alive"))
    assert d.score >= 0.90                       # band said auto...
    assert d.outcome is Outcome.NOTIFY_ONLY      # ...tier C capped it
    assert d.cap_applied == "tier_c_never_auto_act"
    assert any(e.name == "tier_c_never_auto_act" for e in d.audit_events)


def test_tier_b_090_094_is_auto_throttle_not_human_and_block_becomes_throttle():
    """Clarification 1 pinned verbatim: B between 0.90–0.94 gets throttled
    automatically (never blocked); NOT downgraded to human approval."""
    eng, _ = engine()
    a = alert("auth_fail_burst", 0.93, tier=ConfidenceTier.B, crit="critical")
    d = eng.evaluate(IncidentStub([a]), Facts(liveness="alive"),
                     severity_override=5)   # push into the 0.90-0.94 window
    assert 0.90 <= d.score < 0.95
    assert d.outcome is Outcome.AUTO_THROTTLE
    assert d.recommendation.action == "throttle_src"   # block -> throttle_src
    assert d.cap_applied == "tier_b_throttle_cap"


def test_tier_b_at_or_above_095_still_never_blocks():
    eng, _ = engine()
    a = alert("volume_spike", 1.0, tier=ConfidenceTier.B, crit="critical")
    d = eng.evaluate(IncidentStub([a]), Facts(liveness="alive"))
    assert d.outcome is Outcome.AUTO_THROTTLE
    assert d.recommendation.action != "block_ip_temp"


def test_tier_a_has_no_extra_cap():
    eng, _ = engine()
    d = eng.evaluate(IncidentStub([alert("volume_spike", 1.0, crit="critical")]),
                     Facts(liveness="alive"))
    assert d.tier == "A"
    assert d.outcome is Outcome.AUTO_ACT
    assert d.cap_applied is None


# --------------------------------------------------------------------- #
# G1 rejection matrix — escalate_to_human in EVERY code path (§10-M3)
# --------------------------------------------------------------------- #
def test_g1_high_score_auto_band_rejected_to_escalate():
    eng, _ = engine(config_view(critical_assets=frozenset({"10.0.0.99"})))
    d = eng.evaluate(IncidentStub(
        [alert("auth_fail_burst", 1.0, crit="critical", dst="10.0.0.99")],
        dst_ip="10.0.0.99"), Facts(liveness="alive"))
    assert d.outcome is Outcome.ESCALATE_HUMAN
    assert d.cap_applied == "critical_assets"
    assert any(e.name == "critical_asset_allowlist_hit" for e in d.audit_events)


def test_g1_survives_blind_spot_combo():
    """Blind-spot + critical combo: vlan row fires first (escalate), G1 still
    emits its event; outcome stays escalate either way."""
    eng, _ = engine(config_view(critical_assets=frozenset({"10.0.0.99"})))
    a = alert("auth_fail_burst", 1.0, crit="critical",
              dst="10.0.0.99", vlan="legacy_lab")
    d = eng.evaluate(IncidentStub([a], dst_ip="10.0.0.99"))
    names = [e.name for e in d.audit_events]
    assert "alert_from_blind_spot_vlan" in names
    assert "critical_asset_allowlist_hit" in names
    assert d.outcome is Outcome.ESCALATE_HUMAN


def test_g1_survives_tier_c_cap():
    """Tier C caps to notify_only — but G1 lifts the verdict back up to
    escalate_human because allowlisted targets get NO automated touch."""
    eng, _ = engine(config_view(critical_assets=frozenset({"10.0.0.99"})))
    a = alert("auth_fail_burst", 1.0, tier=ConfidenceTier.C,
              crit="critical", dst="10.0.0.99")
    d = eng.evaluate(IncidentStub([a], dst_ip="10.0.0.99"),
                     Facts(liveness="alive"), severity_override=5)
    assert d.tier == "C"
    assert d.outcome is Outcome.ESCALATE_HUMAN
    names = [e.name for e in d.audit_events]
    assert "tier_c_never_auto_act" in names          # cap recorded (P6)
    assert "critical_asset_allowlist_hit" in names   # then G1 overrode


def test_g1_survives_asymmetric_downgrade_path():
    """Asymmetric-high would downgrade block->throttle; on an allowlisted
    target the decision escalates instead (G1 precedes, no exception)."""
    eng, _ = engine(config_view(asymmetric_risk="high",
                                critical_assets=frozenset({"10.0.0.99"})))
    d = eng.evaluate(IncidentStub(
        [alert("auth_fail_burst", 1.0, crit="critical", dst="10.0.0.99")],
        dst_ip="10.0.0.99"), Facts(liveness="alive"))
    assert d.outcome is Outcome.ESCALATE_HUMAN
    names = [e.name for e in d.audit_events]
    assert "asymmetric_routing_risk" in names
    assert "critical_asset_allowlist_hit" in names


def test_g1_survives_rate_breach_path():
    """Rate limiter exhausted + allowlisted target: escalate wins (first
    override), rate alarm still emitted (P6 full path)."""
    clk = FakeClock()
    lim = RateLimiter(max_per_min=5, max_per_hour=20)
    eng, _ = engine(config_view(critical_assets=frozenset({"10.0.0.99"})),
                    clock=clk, limiter=lim)
    # fill the per-minute window with would-be blocks on a NORMAL host
    # (dst must NOT be allowlisted, else G1 escalates and nothing records;
    # both the alert dst AND the stub's incident-level dst_ip matter)
    for _ in range(5):
        eng.evaluate(
            IncidentStub([alert("auth_fail_burst", 1.0, crit="critical",
                                dst="10.0.0.77")], dst_ip="10.0.0.77"),
            Facts(liveness="alive"), severity_override=5)
    d = eng.evaluate(IncidentStub(
        [alert("auth_fail_burst", 1.0, crit="critical", dst="10.0.0.99")],
        dst_ip="10.0.0.99"), Facts(liveness="alive"), severity_override=5)
    assert d.outcome is Outcome.ESCALATE_HUMAN
    names = [e.name for e in d.audit_events]
    assert "rate_limit_breach_alarm" in names
    assert "critical_asset_allowlist_hit" in names


def test_g1_does_not_fire_for_non_aggressive_playbooks():
    """scan/dns_tunneling notify anyway — no G1 event on allowlisted target."""
    eng, _ = engine(config_view(critical_assets=frozenset({"10.0.0.99"})))
    a = alert("scan", 1.0, crit="critical", dst="10.0.0.99")
    d = eng.evaluate(IncidentStub([a], dst_ip="10.0.0.99"),
                     Facts(liveness="alive"))
    assert all(e.name != "critical_asset_allowlist_hit"
               for e in d.audit_events)


# --------------------------------------------------------------------- #
# asymmetric routing risk (action-level downgrade)
# --------------------------------------------------------------------- #
def test_asymmetric_high_downgrades_block_to_throttle_src():
    eng, _ = engine(config_view(asymmetric_risk="high"))
    d = eng.evaluate(IncidentStub(
        [alert("auth_fail_burst", 1.0, crit="critical")]),
        Facts(liveness="alive"), severity_override=5)
    assert d.outcome is Outcome.AUTO_ACT            # outcome untouched
    assert d.recommendation.action == "throttle_src"  # action downgraded
    assert any(e.name == "asymmetric_routing_risk" for e in d.audit_events)


def test_asymmetric_medium_leaves_block_intact():
    eng, _ = engine()   # default medium
    d = eng.evaluate(IncidentStub(
        [alert("auth_fail_burst", 1.0, crit="critical")]),
        Facts(liveness="alive"), severity_override=5)
    assert d.recommendation.action == "block_ip_temp"
    assert all(e.name != "asymmetric_routing_risk" for e in d.audit_events)


# --------------------------------------------------------------------- #
# human approval lifecycle — injected clock only (clarification 2)
# --------------------------------------------------------------------- #
def test_approval_within_window_granted_records_auto_act():
    clk = FakeClock()
    eng, _ = engine(clock=clk)
    d = eng.evaluate(IncidentStub([alert("auth_fail_burst", 0.93,
                                         crit="critical")]),
                     Facts(liveness="alive"))
    assert d.outcome is Outcome.HUMAN_APPROVAL
    clk.advance(minutes=14)                          # inside the window
    resolved = eng.resolve(d.incident_id, approved=True)
    assert resolved.outcome is Outcome.AUTO_ACT
    assert any(e.name == "human_approval_granted" for e in resolved.audit_events)


def test_approval_timeout_after_15_min_degrades_to_notify_only():
    clk = FakeClock()
    eng, _ = engine(clock=clk)
    d = eng.evaluate(IncidentStub([alert("auth_fail_burst", 0.93,
                                         crit="critical")]),
                     Facts(liveness="alive"))
    clk.advance(seconds=APPROVAL_WINDOW_S + 1)       # past the deadline
    resolved = eng.resolve(d.incident_id, approved=True)
    assert resolved.outcome is Outcome.NOTIFY_ONLY
    names = [e.name for e in resolved.audit_events]
    assert "human_approval_timeout" in names          # Q5 verbatim
    assert resolved.recommendation.action == "notify_only"


def test_approval_denied_within_window_is_notify_only():
    clk = FakeClock()
    eng, _ = engine(clock=clk)
    d = eng.evaluate(IncidentStub([alert("auth_fail_burst", 0.93,
                                         crit="critical")]),
                     Facts(liveness="alive"))
    clk.advance(minutes=5)
    resolved = eng.resolve(d.incident_id, approved=False)
    assert resolved.outcome is Outcome.NOTIFY_ONLY
    assert any(e.name == "human_approval_denied" for e in resolved.audit_events)


def test_resolve_unknown_id_raises_keyerror():
    eng, _ = engine()
    with pytest.raises(KeyError):
        eng.resolve("nope", approved=True)


# --------------------------------------------------------------------- #
# G4 rate limiter — per-minute and per-hour windows independently
# --------------------------------------------------------------------- #
def test_rate_limiter_per_minute_breach_downgrades_to_notify_only():
    clk = FakeClock()
    lim = RateLimiter(max_per_min=2, max_per_hour=20)
    eng, _ = engine(limiter=lim, clock=clk)
    outcomes = []
    for _ in range(3):
        d = eng.evaluate(
            IncidentStub([alert("auth_fail_burst", 1.0, crit="critical")]),
            Facts(liveness="alive"), severity_override=5)
        outcomes.append(d)
    assert outcomes[0].outcome is Outcome.AUTO_ACT
    assert outcomes[1].outcome is Outcome.AUTO_ACT
    assert outcomes[2].outcome is Outcome.NOTIFY_ONLY   # third block breaches
    names = [e.name for e in outcomes[2].audit_events]
    assert "rate_limit_breach_alarm" in names
    assert "max_blocks_per_min" in outcomes[2].audit_events[-1].detail


def test_rate_limiter_per_hour_window_independent():
    clk = FakeClock()
    lim = RateLimiter(max_per_min=5, max_per_hour=6)
    eng, _ = engine(limiter=lim, clock=clk)
    for i in range(6):
        clk.advance(minutes=1)                    # never >5/min...
        d = eng.evaluate(
            IncidentStub([alert("auth_fail_burst", 1.0, crit="critical")]),
            Facts(liveness="alive"), severity_override=5)
        if i < 5:
            assert d.outcome is Outcome.AUTO_ACT
    clk.advance(minutes=1)
    d7 = eng.evaluate(
        IncidentStub([alert("auth_fail_burst", 1.0, crit="critical")]),
        Facts(liveness="alive"), severity_override=5)
    assert d7.outcome is Outcome.NOTIFY_ONLY      # ...but the hour fills up
    assert "max_blocks_per_hour" in d7.audit_events[-1].detail


def test_rate_limiter_windows_slide_with_clock():
    clk = FakeClock()
    lim = RateLimiter(max_per_min=1, max_per_hour=10)
    eng, _ = engine(limiter=lim, clock=clk)
    first = eng.evaluate(
        IncidentStub([alert("auth_fail_burst", 1.0, crit="critical")]),
        Facts(liveness="alive"), severity_override=5)
    assert first.outcome is Outcome.AUTO_ACT
    clk.advance(seconds=61)                       # old block slides out
    second = eng.evaluate(
        IncidentStub([alert("auth_fail_burst", 1.0, crit="critical")]),
        Facts(liveness="alive"), severity_override=5)
    assert second.outcome is Outcome.AUTO_ACT


def test_rate_limiter_rejects_bad_limits():
    with pytest.raises(ValueError):
        RateLimiter(0, 5)
    with pytest.raises(ValueError):
        RateLimiter(5, 0)


# --------------------------------------------------------------------- #
# dry-run parity + determinism (binding 1)
# --------------------------------------------------------------------- #
def test_same_inputs_same_decision_and_no_network_touch():
    def build():
        eng, _ = engine()
        return eng.evaluate(
            IncidentStub([alert("auth_fail_burst", 0.93, crit="critical")]))
    d1, d2 = build(), build()
    assert d1.outcome == d2.outcome
    assert d1.score == d2.score
    assert [e.name for e in d1.audit_events] == \
           [e.name for e in d2.audit_events]
    assert d1.would.startswith("would ")          # "would do X because Y"


def test_engine_never_invents_facts_default_is_unknown_liveness():
    """Default Facts() has liveness=unknown -> safe log_only downgrade,
    proving absence is treated as a fact pattern, not guessed alive."""
    eng, _ = engine()
    d = eng.evaluate(IncidentStub([alert("volume_spike", 1.0, crit="critical")]))
    assert d.outcome is Outcome.LOG_ONLY
    assert any(e.name == "liveness_unknown_treated_stale"
               for e in d.audit_events)


def test_severity_override_is_the_phase2_siem_seam():
    eng, _ = engine()
    d_default = eng.evaluate(
        IncidentStub([alert("scan", 0.99, crit="critical")]),
        Facts(liveness="alive"))                               # sev 2
    d_boosted = eng.evaluate(
        IncidentStub([alert("scan", 0.99, crit="critical")]),
        Facts(liveness="alive"), severity_override=5)          # SIEM enrich
    assert d_default.score < d_boosted.score
    assert d_default.outcome is Outcome.LOG_ONLY               # 0.396
    assert d_boosted.outcome is Outcome.AUTO_ACT               # 0.99


def test_empty_incident_refused():
    eng, _ = engine()
    with pytest.raises(ValueError, match="no alerts"):
        eng.evaluate(IncidentStub([]))
