"""Benign SSH session generator (Q2) — normal admin activity.

Successful logins + a few commands; NO attack signal ⇒ these become
FP-rate candidates only if they correlate into flagged incidents.
"""
from __future__ import annotations

from typing import Any

from tools.attackers.common import make_eve_record, rng_for


def generate(*, seed: int = 7, src_ip: str = "10.0.0.200",
             dst_ip: str = "10.0.0.4", start_offset_s: float = 60.0,
             sessions: int = 8) -> list[dict[str, Any]]:
    """Return `sessions` benign ssh flow records."""
    rng = rng_for(seed, "benign_ssh")
    events: list[dict[str, Any]] = []
    for i in range(sessions):
        events.append(make_eve_record(
            ts_offset=start_offset_s + i * rng.uniform(20, 90),
            src_ip=src_ip, dst_ip=dst_ip,
            src_port=rng.randint(40000, 60000), dst_port=22,
            proto="tcp", signal="", family=None,
            confidence=0.5, severity=1, signature_id=0))
    return events
