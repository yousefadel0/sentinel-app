"""P0 — every number comes from evidence, is explainable, and is labelled."""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone

import pytest

from sentinel.capture.confidence import (UNKNOWN_FLOOR, noisy_or,
                                         suricata_confidence, wazuh_confidence)
from sentinel.capture.live import LiveEveDataSource, LiveZeekDataSource
from sentinel.decision.chain import Facts
from sentinel.ui import analytics, pages
from tests.fixtures.decision.helpers import FakeClock, IncidentStub, alert, engine
from tests.test_live_capture import _append, _daemon


# -- confidence is derived from real Suricata / Wazuh fields --------------------

def test_suricata_confidence_uses_real_fields_in_priority_order():
    sev = lambda n: {"alert": {"severity": n}}
    assert suricata_confidence(sev(1)) == 0.85
    assert suricata_confidence(sev(2)) == 0.70
    assert suricata_confidence(sev(3)) == 0.55
    assert suricata_confidence({"alert": {"severity": 1, "metadata": {"confidence": ["Low"]}}}) == 0.50
    assert suricata_confidence({"alert": {"severity": 3, "confidence": 0.93}}) == 0.93
    assert suricata_confidence({"alert": {}}) == UNKNOWN_FLOOR       # no field => floor
    assert suricata_confidence({"event_type": "dns"}) == UNKNOWN_FLOOR
    assert suricata_confidence({"alert": {"severity": True}}) == UNKNOWN_FLOOR


def test_wazuh_confidence_scales_with_rule_level():
    assert wazuh_confidence(5) < wazuh_confidence(10) < wazuh_confidence(15) <= 0.95
    assert wazuh_confidence(None) == UNKNOWN_FLOOR
    assert wazuh_confidence(99) == UNKNOWN_FLOOR


def test_noisy_or_is_monotonic_and_capped():
    assert noisy_or([0.8]) == 0.8
    assert noisy_or([0.8, 0.7]) == pytest.approx(0.94, abs=1e-3)
    assert noisy_or([0.99, 0.99, 0.99]) <= 0.99


def test_live_eve_no_longer_fabricates_half(tmp_path):
    f = tmp_path / "eve.json"
    ev = {"timestamp": "2026-10-20T08:00:01+0000", "event_type": "alert",
          "src_ip": "203.0.113.7", "dest_ip": "10.0.0.4", "src_port": 1,
          "dest_port": 22, "proto": "TCP",
          "alert": {"signature": "ET SCAN", "severity": 1}}
    _append(f, json.dumps(ev) + "\n")
    a = LiveEveDataSource(f).fetch()[0]
    assert a.confidence_raw == 0.85                  # from severity, not 0.5


def test_zeek_notice_scan_becomes_real_evidence(tmp_path):
    f = tmp_path / "notice.log"
    hdr = ("#fields\tts\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tnote\n"
           "#types\ttime\taddr\tport\taddr\tport\tstring\n")
    _append(f, hdr + "1697792401.5\t203.0.113.9\t0\t10.0.0.4\t0\tScan::Port_Scan\n"
                     "1697792402.5\t203.0.113.9\t0\t10.0.0.4\t0\tSSL::Invalid_Server_Cert\n")
    alerts = LiveZeekDataSource(f).fetch()
    scan = [a for a in alerts if "scan" in a.signals]
    other = [a for a in alerts if "scan" not in a.signals]
    assert len(scan) == 1 and scan[0].confidence_raw == 0.80
    assert len(other) == 1 and other[0].confidence_raw == UNKNOWN_FLOOR


# -- engine: independent sources corroborate each other -------------------------

def _inc(*specs):
    from dataclasses import replace
    from sentinel.models import SourceRef
    alerts = []
    for adapter, conf in specs:
        a = alert("auth_fail_burst", conf, crit="critical")
        alerts.append(replace(a, source=SourceRef(adapter=adapter, ref="x")))
    return IncidentStub(alerts)


def test_corroboration_raises_confidence_only_across_independent_sources():
    eng, _ = engine(clock=FakeClock())
    one = eng.evaluate(_inc(("eve_json", 0.80)), Facts(liveness="alive"))
    two = eng.evaluate(_inc(("eve_json", 0.80), ("behavioral", 0.85)),
                       Facts(liveness="alive"))
    same = eng.evaluate(_inc(("eve_json", 0.80), ("eve_json", 0.85)),
                        Facts(liveness="alive"))
    assert one.inputs["confidence"] == 0.80
    assert two.inputs["confidence"] == pytest.approx(0.97, abs=1e-3)
    assert two.inputs["confidence_sources"] == {"eve_json": 0.8, "behavioral": 0.85}
    assert same.inputs["confidence"] == 0.85         # same sensor twice: no boost
    assert two.score > one.score


# -- the explanation must equal what the engine computed ------------------------

def test_recorded_inputs_reproduce_the_engine_base_score(tmp_path):
    base = datetime(2026, 10, 20, 8, 0, 0, tzinfo=timezone.utc)
    now = [base + timedelta(seconds=30)]
    d, store = _daemon(tmp_path, now)
    _append(tmp_path / "eve.json", json.dumps({
        "timestamp": "2026-10-20T08:00:01+0000", "event_type": "alert",
        "src_ip": "203.0.113.7", "dest_ip": "192.168.4.11", "src_port": 1,
        "dest_port": 22, "proto": "TCP", "sentinel_signal": "scan",
        "alert": {"severity": 1}}) + "\n")
    d.run_once()
    full = analytics.incident_full(store, store.rows("decisions")[0]["incident_id"])
    inp = full["inputs"]
    dec = full["decisions"][0]
    w = {"critical": 1.0, "high": 0.85, "medium": 0.65, "low": 0.45}[inp["criticality"]]
    assert inp["confidence"] * w * inp["severity"] / 5 == pytest.approx(dec["base_score"], abs=1e-4)
    html = pages.incident_detail(full, True)
    assert "لماذا هذه الدرجة" in html and "85%" in html
    store.close()


# -- origin: replay is never silently mixed with live ---------------------------

def _seed(store, case_id, iid, ts_first=None):
    store.record_decision(case_id=case_id, incident_id=iid, outcome="log_only",
                          score=0.3, base_score=0.3, tier="A", cap_applied=None,
                          would="w", recommendation={}, audit_events=[])
    store.record_incident_context(
        incident_id=iid, src_ip="1.1.1.1", dst_ip="2.2.2.2", attack_type="Brute force",
        signals=["auth_fail_burst"], alert_count=3,
        first_ts=ts_first or "2026-10-20T08:00:00+00:00",
        last_ts="2026-10-20T08:01:00+00:00", evidence=[], mitre=[])


def test_origin_separation_default_and_banner(tmp_path):
    from sentinel.auditstore.store import Store
    store = Store(tmp_path / "a.sqlite")
    _seed(store, "pilot", "inc-replay-1")
    _seed(store, "pilot", "inc-replay-2")
    ov = analytics.overview(store)
    assert ov["origin"] == "" and ov["origins"] == {"live": 0, "replay": 2}
    assert "replay" in pages.overview(ov, analytics.autonomy_readiness(ov, 0), {}, 0)
    _seed(store, "live", "inc-live-1")
    ov = analytics.overview(store)
    assert ov["origin"] == "live" and ov["incidents"] == 1          # live by default
    assert analytics.overview(store, origin="replay")["incidents"] == 2
    assert analytics.incident_list(store, origin="live")["total"] == 1
    rows = analytics.incident_list(store)["rows"]
    assert {r["origin"] for r in rows} == {"live", "replay"}
    store.close()


def test_latency_is_measured_only_from_live_incidents(tmp_path):
    from sentinel.auditstore.store import Store
    import sentinel.auditstore.store as st
    store = Store(tmp_path / "a.sqlite")
    for i, delay in enumerate((4, 6, 10)):
        t0 = datetime.now(timezone.utc) - timedelta(seconds=delay)
        _seed(store, "live", f"inc-{i}", ts_first=t0.isoformat())
    _seed(store, "pilot", "inc-p", ts_first="2020-01-01T00:00:00+00:00")
    lat = analytics.decision_latency(store)
    assert lat["n"] == 3                          # replay ignored, no fake 5-year value
    assert 5 <= lat["median_s"] <= 7
    store.close()
    empty = Store(tmp_path / "b.sqlite")
    assert analytics.decision_latency(empty) == {"n": 0, "median_s": None, "p90_s": None}
    empty.close()
