"""Shared attacker/benign generator plumbing (M6, D6).

Generators are COMMITTED tools producing deterministic eve.json-shaped
records given a seed and timeline. They never touch the network — the
harness writes their output into capture fixtures that ride the existing
M1 file adapters (D3/D7). scapy is NOT imported here; volumetric pcap
generation lives in tools/make_fixtures.py as a dev-extra step.

Record convention: each emitted dict is a valid Suricata eve record AND
carries two harness-private keys consumed by the pilot runner:
* ``sentinel_signal``  — attack-family signal label fed to normalize()
  ("" for benign events ⇒ no attack signal).
* ``sentinel_truth``   — {"kind": "attack"|"benign", "family": str} used
  to build ground truth for MTTD / FP-rate attribution.
"""
from __future__ import annotations

import json
import random
from datetime import datetime, timedelta, timezone
from typing import Any

BASE_TS = datetime(2026, 1, 15, tzinfo=timezone.utc)

SIGNAL_FAMILIES = {
    "scan": ("scan", 2),
    "auth_fail_burst": ("brute_force", 4),
    "volume_spike": ("ddos_volumetric", 5),
    "beacon_periodic": ("c2_beacon", 4),
    "dns_tunneling": ("dns_tunneling", 3),
}


def ts_at(offset_seconds: float) -> str:
    """Deterministic ISO timestamp BASE_TS + offset."""
    return (BASE_TS + timedelta(seconds=offset_seconds)).isoformat()


def rng_for(seed: int, name: str) -> random.Random:
    """Seeded RNG — same seed+name ⇒ byte-identical output forever."""
    return random.Random(f"{name}:{seed}")


def make_eve_record(*, ts_offset: float, src_ip: str, dst_ip: str,
                    src_port: int, dst_port: int, proto: str,
                    signal: str, family: str | None, confidence: float,
                    severity: int, signature_id: int) -> dict[str, Any]:
    """One eve-shaped record with harness-private truth keys attached."""
    rec: dict[str, Any] = {
        "timestamp": ts_at(ts_offset),
        "src_ip": src_ip,
        "dest_ip": dst_ip,
        "src_port": src_port,
        "dest_port": dst_port,
        "proto": proto,
        "event_type": "alert" if signal else "flow",
    }
    if signal:
        rec["alert"] = {
            "signature_id": signature_id,
            "severity": severity,
            "confidence": round(confidence, 3),
        }
    rec["sentinel_signal"] = signal
    rec["sentinel_truth"] = {"kind": "attack" if signal else "benign",
                             "family": family or ""}
    return rec


def write_events(path, events: list[dict[str, Any]]) -> int:
    """Append events as JSONL; returns bytes written (determinism aid)."""
    blob = "".join(json.dumps(e, sort_keys=True) + "\n" for e in events)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(blob, encoding="utf-8")
    return len(blob.encode("utf-8"))
