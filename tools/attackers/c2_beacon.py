"""C2 beacon generator — deterministic eve records (M6, D6).

Emits a compromised host phoning home to a fixed C2 destination on a
fixed period; carries the ``beacon_periodic`` signal → C2_BEACON
playbook (quarantine_asset).
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from tools.attackers.common import SIGNAL_FAMILIES, make_eve_record


def generate(*, seed: int = 42, src_ip: str = "10.0.0.4",
             dst_ip: str = "203.0.113.66", start_offset_s: float = 1200.0,
             beacons: int = 12, period_s: float = 30.0) -> list[dict[str, Any]]:
    """Return `beacons` periodic egress alerts, `period_s` apart."""
    signal, sev = SIGNAL_FAMILIES["beacon_periodic"]
    events: list[dict[str, Any]] = []
    for i in range(beacons):
        events.append(make_eve_record(
            ts_offset=start_offset_s + i * period_s,
            src_ip=src_ip, dst_ip=dst_ip,
            src_port=49152 + (i % 100), dst_port=443,
            proto="tcp", signal=signal, family="c2_beacon",
            confidence=0.88, severity=sev, signature_id=2027870))
    return events
