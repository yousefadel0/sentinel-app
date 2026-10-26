"""Gate A (§10-M2): fixture attack-chains merge into SINGLE incidents.

Both directions proven per operator reminder #1:
  * positive — chains that MUST merge do merge;
  * negative — gaps > window and different endpoints MUST split.
"""
from __future__ import annotations

import pytest

from sentinel.correlator import (
    DEFAULT_CORRELATION_WINDOW_S,
    Correlator,
    Incident,
)
from sentinel.models import Alert, AlertMeta, AssetHint, ConfidenceTier, SourceRef


def make_alert(
    alert_id: str,
    ts: str,
    src_ip: str = "203.0.113.7",
    dst_ip: str = "192.168.4.11",
    signals: tuple[str, ...] = ("auth_fail_burst",),
) -> Alert:
    return Alert(
        alert_id=alert_id,
        ts=ts,
        source=SourceRef(adapter="eve_json", ref=f"{alert_id}.jsonl#1"),
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=44444,
        dst_port=22,
        protocol="tcp",
        vlan=None,
        asset_hint=AssetHint(),
        signals=signals,
        confidence_raw=0.9,
        confidence_tier=ConfidenceTier.A,
        meta=AlertMeta(raw_payload_hash="deadbeef"),
    )


def brute_force_chain(n: int = 7, gap_s: int = 300, start="2026-06-01T08:00:00+00:00"):
    """Fixture chain: n alerts, `gap_s` apart — a classic SSH brute force."""
    from datetime import datetime, timedelta

    t0 = datetime.fromisoformat(start)
    out = []
    for i in range(n):
        ts = (t0 + timedelta(seconds=i * gap_s)).isoformat()
        sigs = ("scan",) if i == 0 else ("auth_fail_burst",)
        out.append(make_alert(f"a{i}", ts, signals=sigs))
    return out


# ---------------------------------------------------------------- positive


def test_brute_force_burst_merges_into_single_incident():
    """THE gate: 30-min burst with 5-min gaps = ONE incident."""
    incidents = Correlator().correlate(brute_force_chain(7))
    assert len(incidents) == 1
    inc = incidents[0]
    assert isinstance(inc, Incident)
    assert len(inc.alerts) == 7
    assert inc.src_ip == "203.0.113.7" and inc.dst_ip == "192.168.4.11"
    assert inc.first_ts.endswith("08:00:00+00:00")
    assert inc.last_ts.endswith("08:30:00+00:00")


def test_cross_family_merge_union_signals_order_stable():
    """scan -> auth_fail_burst from same src/dst is ONE escalating thread."""
    alerts = brute_force_chain(3)
    # appended AFTER the last chain member (08:10) -> escalation tail
    alerts += [make_alert("x9", "2026-06-01T08:12:00+00:00",
                          signals=("beacon_periodic",))]
    incidents = Correlator().correlate(alerts)
    assert len(incidents) == 1
    # union of families, first-seen order preserved (deterministic for M3)
    assert incidents[0].signals == ("scan", "auth_fail_burst", "beacon_periodic")


def test_unsorted_input_tolerated_and_sorted_by_ts():
    shuffled = list(reversed(brute_force_chain(5)))
    incidents = Correlator().correlate(shuffled)
    assert len(incidents) == 1
    ts_list = [a.ts for a in incidents[0].alerts]
    assert ts_list == sorted(ts_list)


def test_single_alert_is_one_singleton_incident():
    incidents = Correlator().correlate([make_alert("solo", "2026-06-01T09:00:00+00:00")])
    assert len(incidents) == 1 and len(incidents[0].alerts) == 1


def test_empty_input_yields_no_incidents():
    assert Correlator().correlate([]) == []


def test_incident_is_frozen_and_id_deterministic():
    inc = Correlator().correlate(brute_force_chain(2))[0]
    with pytest.raises(Exception):
        inc.src_ip = "10.0.0.1"  # type: ignore[misc]
    again = Correlator().correlate(brute_force_chain(2))[0]
    assert inc.incident_id == again.incident_id  # uuid5 over member ids
    assert inc.incident_id.startswith("inc-")


# ---------------------------------------------------------------- negative


def test_gap_over_window_splits_chain_into_two_incidents():
    """Reminder #1a: one silent gap > 900s SPLITS the chain."""
    alerts = brute_force_chain(3, gap_s=300)          # 08:00 .. 08:10
    alerts += [make_alert("late", "2026-06-01T08:26:00+00:00")]  # +16 min gap
    incidents = Correlator().correlate(alerts)
    assert len(incidents) == 2
    assert [len(i.alerts) for i in incidents] == [3, 1]


def test_same_dst_different_src_stays_separate():
    a = make_alert("a", "2026-06-01T08:00:00+00:00")
    b = make_alert("b", "2026-06-01T08:05:00+00:00", src_ip="203.0.113.99")
    assert len(Correlator().correlate([a, b])) == 2


def test_same_src_different_dst_stays_separate():
    a = make_alert("a", "2026-06-01T08:00:00+00:00")
    b = make_alert("b", "2026-06-01T08:05:00+00:00", dst_ip="192.168.4.12")
    assert len(Correlator().correlate([a, b])) == 2


# ------------------------------------------------------------- boundaries


def test_exactly_window_gap_merges_and_one_second_more_splits():
    w = DEFAULT_CORRELATION_WINDOW_S
    assert w == 900 and isinstance(w, int)  # documented module constant
    at_limit = [
        make_alert("a", "2026-06-01T08:00:00+00:00"),
        make_alert("b", "2026-06-01T08:15:00+00:00"),   # exactly 900s
    ]
    assert len(Correlator().correlate(at_limit)) == 1

    over = [
        make_alert("a", "2026-06-01T08:00:00+00:00"),
        make_alert("b", "2026-06-01T08:15:01+00:00"),   # 901s
    ]
    assert len(Correlator().correlate(over)) == 2


def test_gap_measured_from_last_alert_not_first():
    """20-min spread with 5-min gaps = ONE incident (operator-pinned)."""
    incidents = Correlator().correlate(brute_force_chain(5, gap_s=300))
    assert len(incidents) == 1
    span = incidents[0].alerts[-1].ts, incidents[0].alerts[0].ts
    assert span[0].endswith("08:20:00+00:00") and span[1].endswith("08:00:00+00:00")


def test_custom_window_is_honored_and_validated():
    c = Correlator(window_s=60)
    alerts = [
        make_alert("a", "2026-06-01T08:00:00+00:00"),
        make_alert("b", "2026-06-01T08:02:00+00:00"),   # 120s > custom 60s
    ]
    assert len(c.correlate(alerts)) == 2
    with pytest.raises(ValueError):
        Correlator(window_s=0)


# -------------------------------------------------- M1 fixtures end-to-end


def test_m1_replay_fixtures_flow_through_correlator():
    """Replay adapters -> typed Alerts -> incidents (integration seam)."""
    from sentinel.capture.adapters_file import EveFileDataSource

    eve = EveFileDataSource(
        "tests/fixtures/capture/sample_eve.jsonl",
        vlan=10,
        critical_assets={"192.168.4.11": "dc-01"},
    )
    alerts = [a for a in eve.fetch() if a.src_ip and a.dst_ip]
    incidents = Correlator().correlate(alerts)
    total_grouped = sum(len(i.alerts) for i in incidents)
    assert total_grouped == len(alerts)          # nothing lost, none duplicated
    # every incident is internally consistent on ONE endpoint pair
    assert all(
        {a.src_ip for a in i.alerts} == {i.src_ip}
        and {a.dst_ip for a in i.alerts} == {i.dst_ip}
        for i in incidents
    )
    pairs = {(i.src_ip, i.dst_ip) for i in incidents}
    assert len(incidents) >= len(pairs)          # splits allowed, merges never cross pairs
