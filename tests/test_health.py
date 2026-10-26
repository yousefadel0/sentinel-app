"""CaptureHealthTracker tests — per-interface roll-up + honest semantics."""
from __future__ import annotations

import time
from datetime import datetime, timezone

from sentinel.capture.health import CaptureHealthTracker


def _iso(stamp: float) -> str:
    return datetime.fromtimestamp(stamp, tz=timezone.utc).isoformat()


def test_never_seen_interface_reports_down():
    t = CaptureHealthTracker(interface="edge_span")
    snap = t.snapshot()
    assert snap.status == "down" and snap.heartbeat_ts is None


def test_fresh_heartbeat_is_healthy_then_staleness_degrades():
    t = CaptureHealthTracker(interface="core_span", stale_after_seconds=0.05)
    t.record_heartbeat(ts=_iso(time.time()))
    assert t.snapshot().status == "healthy"
    time.sleep(0.3)  # >> stale window: Windows clock granularity is ~16 ms
    assert t.snapshot().status == "degraded"


def test_drop_counters_are_sensor_reported_max_not_invented():
    t = CaptureHealthTracker(interface="edge_span")
    t.record_drops(3)
    t.record_drops(7)
    t.record_heartbeat(drops=5)
    assert t.snapshot().packet_drops == 7          # max seen, never fabricated


def test_last_alert_ts_recorded_from_alert_stream():
    t = CaptureHealthTracker(interface="edge_span")
    t.record_alert(ts="2026-10-20T08:00:01+00:00")
    assert t.snapshot().last_alert_ts == "2026-10-20T08:00:01+00:00"


def test_coverage_stub_against_asset_inventory():
    t = CaptureHealthTracker(interface="edge_span")
    t.set_inventory_size(4)
    t.note_asset_seen()
    t.note_asset_seen()
    snap = t.snapshot()
    assert snap.coverage_percent == 50.0           # 2/4 — honest stub math
    t.note_asset_seen(); t.note_asset_seen()
    assert t.snapshot().coverage_percent == 100.0
    capped = CaptureHealthTracker(interface="x")
    capped.set_inventory_size(1)
    for _ in range(9):
        capped.note_asset_seen()
    assert capped.snapshot().coverage_percent == 100.0   # capped, not >100


def test_interfaces_are_independent_rollup_is_per_interface():
    a = CaptureHealthTracker(interface="edge_span", stale_after_seconds=0.05)
    b = CaptureHealthTracker(interface="core_span")
    a.record_heartbeat()
    time.sleep(0.3)  # >> stale window: Windows clock granularity is ~16 ms
    assert a.snapshot().status == "degraded"
    assert b.snapshot().status == "down"           # untouched interface unaffected


def test_snapshot_shape_matches_datasource_contract_keys():
    snap = CaptureHealthTracker(interface="edge_span").snapshot(
        source_type="file_replay").to_dict()
    assert set(snap) >= {"status", "heartbeat_ts", "packet_drops",
                         "coverage_percent", "last_alert_ts", "source_type"}
