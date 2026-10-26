"""Port-scan generator — deterministic eve records (M6, D6).

Emits a rapid SYN sweep across a port range from one source to one
destination; each packet is an ``alert`` record carrying the ``scan``
signal so the pilot's normalize() path tags it for the SCAN playbook.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from tools.attackers.common import SIGNAL_FAMILIES, make_eve_record, rng_for


def generate(*, seed: int = 42, src_ip: str = "203.0.113.10",
             dst_ip: str = "10.0.0.4", start_offset_s: float = 0.0,
             ports: int = 40) -> list[dict[str, Any]]:
    """Return `ports` scan events, 0.2s apart, deterministic under seed."""
    rng = rng_for(seed, "scan")
    signal, sev = SIGNAL_FAMILIES["scan"]
    events: list[dict[str, Any]] = []
    for i in range(ports):
        events.append(make_eve_record(
            ts_offset=start_offset_s + i * 0.2,
            src_ip=src_ip, dst_ip=dst_ip,
            src_port=rng.randint(40000, 60000),
            dst_port=1024 + (i * 37) % 63000,
            proto="tcp", signal=signal, family="scan",
            confidence=round(0.55 + rng.random() * 0.1, 3),
            severity=sev, signature_id=2001218))
    return events
