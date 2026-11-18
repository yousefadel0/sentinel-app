"""Phase 1 hardening: real liveness, risk floor, Suricata noise suppression."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

from sentinel.capture import normalizer
from sentinel.capture.liveness import FlowLiveness
from sentinel.capture.normalizer import configure_noise, is_sensor_noise, normalize
from sentinel.decision import DecisionEngine, AutonomyController, RateLimiter
from sentinel.decision.chain import Facts
from sentinel.decision.models import Outcome
from sentinel.detectors.suite import is_incident_worthy
from tests.fixtures.decision.helpers import FakeClock, IncidentStub, alert, config_view

T0 = datetime(2026, 11, 18, 12, 0, tzinfo=timezone.utc)


def _flow(src, dst, ts):
    return SimpleNamespace(src_ip=src, dst_ip=dst, ts=ts.isoformat())


# -- liveness ---------------------------------------------------------------
def test_liveness_alive_stale_unknown_from_flows():
    now = [T0]
    lv = FlowLiveness(window_s=600, clock=lambda: now[0])
    lv.observe([_flow("203.0.113.9", "10.0.0.4", T0 - timedelta(seconds=30))])
    assert lv({"src_ip": "203.0.113.9"}) == "alive"
    assert lv({"src_ip": "198.51.100.1"}) == "unknown"
    now[0] = T0 + timedelta(minutes=20)
    assert lv({"src_ip": "203.0.113.9"}) == "stale"


def test_liveness_ignores_garbage_and_keeps_latest():
    lv = FlowLiveness(clock=lambda: T0)
    lv.observe([SimpleNamespace(src_ip="1.1.1.1", dst_ip="", ts="not-a-date"),
                _flow("1.1.1.1", "", T0 - timedelta(hours=2)),
                _flow("1.1.1.1", "", T0 - timedelta(seconds=5))])
    assert lv({"src_ip": "1.1.1.1"}) == "alive"


def test_liveness_bounded_memory():
    lv = FlowLiveness(clock=lambda: T0, max_tracked=10)
    lv.observe([_flow(f"10.1.0.{i}", "", T0 - timedelta(seconds=i))
                for i in range(30)])
    assert lv.snapshot()["tracked"] <= 10


# -- risk floor --------------------------------------------------------------
def _engine(**cfg):
    clock = FakeClock()
    return DecisionEngine(config_view=config_view(**cfg), clock=clock,
                          rate_limiter=RateLimiter(5, 20),
                          controller=AutonomyController(level=0))


def test_low_risk_noise_is_logged_not_reported():
    """The field bug: conf 0.55 on a low-value host scored 0.099 yet was
    put in report_wait. Below the risk floor it is logged only."""
    eng = _engine(report_threshold=0.50, min_risk_score=0.20)
    d = eng.evaluate(IncidentStub([alert("scan", 0.55, crit="low")]),
                     Facts(liveness="alive"))
    assert d.score < 0.20
    assert d.outcome is Outcome.LOG_ONLY
    assert any(e.name == "below_risk_floor" for e in d.audit_events)
    assert "risk score fell below" in d.would


def test_risk_floor_keeps_real_attacks():
    eng = _engine(report_threshold=0.50, min_risk_score=0.20)
    d = eng.evaluate(IncidentStub([alert("auth_fail_burst", 0.85, crit="critical")]),
                     Facts(liveness="alive"))
    assert d.outcome is Outcome.HUMAN_APPROVAL


def test_log_only_reason_names_the_real_cause():
    eng = _engine()
    d = eng.evaluate(IncidentStub([alert("volume_spike", 1.0, crit="critical")]),
                     Facts(liveness="stale"))
    assert d.outcome is Outcome.LOG_ONLY
    assert "confidence fell below" not in d.would
    assert "liveness" in d.would


# -- Suricata noise -----------------------------------------------------------
def _eve(sid):
    return {"timestamp": "2026-11-18T12:40:23.315232+0000", "event_type": "alert",
            "src_ip": "10.0.0.1", "dest_ip": "10.0.0.2", "proto": "TCP",
            "alert": {"signature_id": sid, "signature": "x", "severity": 3}}


@pytest.fixture(autouse=True)
def _reset_noise():
    configure_noise()
    yield
    configure_noise()


def test_engine_events_are_telemetry_not_incidents():
    a = normalize(_eve(2200121), adapter="eve_json", ref="eve.json#1")
    assert is_sensor_noise(_eve(2200121))
    assert "signature_hit" not in a.signals
    assert not is_incident_worthy(a)


def test_real_signatures_still_open_incidents():
    a = normalize(_eve(2001219), adapter="eve_json", ref="eve.json#2")
    assert "signature_hit" in a.signals
    assert is_incident_worthy(a)


def test_operator_suppression_list_and_opt_out():
    configure_noise(suppress_signature_ids=[2001219])
    assert is_sensor_noise(_eve(2001219))
    configure_noise(suppress_engine_events=False)
    assert not is_sensor_noise(_eve(2200121))
    assert normalizer.ENGINE_EVENT_SID_RANGE == (2200000, 2299999)
