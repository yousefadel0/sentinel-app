"""File/replay adapter tests — fixtures -> typed Alerts (§10-M1 gate).

Also proves the HONEST health semantics required by the operator:
source_type="file_replay", documented-zero packet_drops, N/A coverage,
mtime-or-ingestion heartbeat with explicit basis.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from sentinel.capture.adapters_file import EveFileDataSource, ZeekLogFileDataSource
from sentinel.models import Alert, ConfidenceTier

FIXTURES = Path(__file__).parent / "fixtures" / "capture"


# ---------- gate: fixtures -> typed Alerts ----------

@pytest.mark.parametrize(
    ("adapter_name", "fixture"),
    [
        ("eve_json", "sample_eve.jsonl"),
        ("zeek_conn", "zeek_conn.log"),
        ("zeek_dns", "zeek_dns.log"),
        ("zeek_ssl", "zeek_ssl.log"),
        ("zeek_notice", "zeek_notice.log"),
    ],
)
def test_fixture_yields_typed_alerts_with_full_field_set(adapter_name, fixture):
    ds = (EveFileDataSource(FIXTURES / fixture) if adapter_name == "eve_json"
          else ZeekLogFileDataSource(FIXTURES / fixture))
    alerts = ds.fetch()
    assert len(alerts) >= 1
    for a in alerts:
        assert isinstance(a, Alert)
        assert a.source.adapter == adapter_name
        assert a.alert_id and a.ts
        assert a.src_ip and a.dst_ip
        assert isinstance(a.src_port, int) and isinstance(a.dst_port, int)
        assert a.protocol
        assert isinstance(a.signals, tuple)
        assert a.confidence_tier is ConfidenceTier.A   # wire-only doctrine


def test_eve_adapter_maps_event_type_into_signals():
    alerts = EveFileDataSource(FIXTURES / "sample_eve.jsonl").fetch()
    by_signal = {a.source.ref: a for a in alerts}
    dns_ref = next(ref for ref, a in by_signal.items() if "dns_event" in a.signals)
    assert by_signal[dns_ref].signals == ("dns_event",)


def test_asset_hint_lookup_by_dest_ip():
    assets = {"192.168.4.11": None}  # placeholder replaced below
    from sentinel.models import AssetHint
    hint_map = {"192.168.4.11": AssetHint(resolved_hostname="dc-01",
                                          criticality="critical")}
    ds = EveFileDataSource(FIXTURES / "sample_eve.jsonl",
                           vlan="prod", critical_assets=hint_map)
    alerts = ds.fetch()
    hit = [a for a in alerts if a.dst_ip == "192.168.4.11"]
    assert hit and all(a.asset_hint.resolved_hostname == "dc-01"
                       for a in hit)
    assert all(a.vlan == "prod" for a in alerts)


# ---------- honest health semantics (operator expectation) ----------

def test_replay_health_is_honest_never_live_looking():
    ds = EveFileDataSource(FIXTURES / "sample_eve.jsonl")
    h = ds.health()
    assert h["source_type"] == "file_replay"       # explicit marker
    assert h["packet_drops"] == 0                  # documented zero, not fake live counter
    assert h["coverage_percent"] is None           # N/A — no fabricated %
    assert h["status"] in ("healthy", "down")


def test_zeek_adapter_health_marks_file_replay_too():
    h = ZeekLogFileDataSource(FIXTURES / "zeek_conn.log").health()
    assert h["source_type"] == "file_replay"
    assert h["packet_drops"] == 0


def test_heartbeat_prefers_mtime_then_falls_back(tmp_path):
    f = tmp_path / "eve.jsonl"
    f.write_text('{"timestamp":"t","event_type":"flow"}\n')
    mtime_iso = ds_heartbeat(f)
    assert mtime_iso["heartbeat_basis"] == "file_mtime"

    missing = tmp_path / "never_existed.jsonl"
    fallback = ds_heartbeat(missing)
    assert fallback["heartbeat_basis"] == "ingestion_time"


def ds_heartbeat(path: Path) -> dict:
    return EveFileDataSource(path).health()


def test_missing_fixture_reports_down_not_crash(tmp_path):
    ds = EveFileDataSource(tmp_path / "ghost.jsonl")
    assert ds.health()["status"] == "down"
    assert ds.fetch() == []                        # P4: degrade, never raise


def test_fetch_twice_is_safe_and_deterministic_refs():
    ds = EveFileDataSource(FIXTURES / "sample_eve.jsonl")
    first = ds.fetch()
    second = EveFileDataSource(FIXTURES / "sample_eve.jsonl").fetch()
    assert [a.source.ref for a in first] == [a.source.ref for a in second]
