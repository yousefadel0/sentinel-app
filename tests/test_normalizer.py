"""Normalizer tests — §4 completeness + CENTRALIZED tier assignment.

Gate focus:
* every Alert carries the full §4 field set (vlan included)
* tier comes from ONE map (ADAPTER_TIERS) — M2 extension touches only it
* raw evidence crosses as sha256 digest, never payload copies
"""
from __future__ import annotations

import pytest

from sentinel.capture.normalizer import ADAPTER_TIERS, assign_tier, normalize
from sentinel.models import AssetHint, ConfidenceTier


def _eve_alert_row():
    return {
        "timestamp": "2026-10-20T08:00:01.123456+0000",
        "event_type": "alert",
        "src_ip": "203.0.113.7",
        "src_port": 4443,
        "dest_ip": "192.168.4.11",
        "dest_port": 22,
        "proto": "TCP",
        "alert": {"signature_id": 2001, "confidence": 0.92},
        "flow": {"duration_seconds": 42.5},
        "packet_count": 50,
        "bytes": 3200,
    }


# ---------- §4 completeness ----------

def test_alert_carries_full_section4_field_set():
    a = normalize(_eve_alert_row(), adapter="eve_json", ref="f.jsonl#1")
    assert a.alert_id and a.ts.startswith("2026-10-20T08:00:01")
    assert a.source.adapter == "eve_json" and a.source.ref == "f.jsonl#1"
    assert (a.src_ip, a.dst_ip) == ("203.0.113.7", "192.168.4.11")
    assert (a.src_port, a.dst_port) == (4443, 22)
    assert a.protocol == "tcp"
    assert isinstance(a.asset_hint, AssetHint)
    assert isinstance(a.signals, tuple)
    assert 0.0 <= a.confidence_raw <= 1.0
    assert a.confidence_tier is ConfidenceTier.A
    assert a.meta.packet_count == 50 and a.meta.byte_count == 3200
    assert a.meta.duration_seconds == 42.5


def test_vlan_and_asset_hint_flow_through():
    hint = AssetHint(resolved_hostname="dc-01", asset_id="a-17",
                     criticality="critical")
    a = normalize(_eve_alert_row(), adapter="eve_json", ref="r#2",
                  vlan="prod", asset_hint=hint)
    assert a.vlan == "prod"
    assert a.asset_hint.resolved_hostname == "dc-01"
    assert a.asset_hint.criticality == "critical"


def test_zeek_field_fallbacks_resolve():
    row = {"ts": "1697792401.123456", "id.orig_h": "203.0.113.7",
           "id.orig_p": 4443, "id.resp_h": "192.168.4.11", "id.resp_p": 22,
           "proto": "tcp"}
    a = normalize(row, adapter="zeek_conn", ref="conn.log#1")
    assert (a.src_ip, a.dst_ip) == ("203.0.113.7", "192.168.4.11")
    assert (a.src_port, a.dst_port) == (4443, 22)


# ---------- centralized tier mapping (M2-extension guard) ----------

def test_all_wire_adapters_are_tier_a():
    for adapter in ("eve_json", "zeek_conn", "zeek_dns", "zeek_ssl",
                    "zeek_notice"):
        assert assign_tier(adapter) is ConfidenceTier.A


def test_tier_map_is_the_single_decision_point(monkeypatch):
    """Adding an adapter to ADAPTER_TIERS changes output WITHOUT touching
    any source module — proving centralization (operator expectation)."""
    monkeypatch.setitem(ADAPTER_TIERS, "siem_identity_feed",
                        ConfidenceTier.C)
    row = {"src_ip": "10.1.1.9", "dest_ip": "10.0.0.4"}
    a = normalize(row, adapter="siem_identity_feed", ref="x#1")
    assert a.confidence_tier is ConfidenceTier.C


def test_unknown_adapter_fails_loudly_not_silently():
    with pytest.raises(KeyError):
        assign_tier("mystery_source")


# ---------- evidence discipline: hash not payload ----------

def test_raw_payload_hash_is_sha256_of_ref_and_no_payload_leak():
    a = normalize(_eve_alert_row(), adapter="eve_json", ref="f.jsonl#7")
    import hashlib
    assert a.meta.raw_payload_hash == hashlib.sha256(b"f.jsonl#7").hexdigest()
    blob = repr(a.to_dict())
    assert "signature_id" not in blob          # raw record fields never copied
    assert "ET SCAN" not in blob


# ---------- folded item 1: event_type mapping ----------

def test_eve_event_type_becomes_signal_hint():
    a = normalize(_eve_alert_row(), adapter="eve_json", ref="r#3")
    assert "suricata_alert" in a.signals and "signature_hit" in a.signals

    dns_row = {"timestamp": "t", "event_type": "dns",
               "src_ip": "10.0.0.1", "dest_ip": "10.0.0.5"}
    b = normalize(dns_row, adapter="eve_json", ref="r#4")
    assert "dns_event" in b.signals


def test_explicit_signals_are_preserved_and_deduped():
    a = normalize(_eve_alert_row(), adapter="eve_json", ref="r#5",
                  signals=("scan", "suricata_alert"))
    assert a.signals[0] == "scan"
    assert a.signals.count("suricata_alert") == 1


# ---------- defaults & bounds ----------

def test_confidence_default_is_neutral_half():
    row = {"src_ip": "1.2.3.4", "dest_ip": "5.6.7.8"}
    a = normalize(row, adapter="zeek_conn", ref="c#9")
    assert a.confidence_raw == 0.5
