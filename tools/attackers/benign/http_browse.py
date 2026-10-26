"""Benign HTTP browsing generator (Q2) — normal user web traffic.

Deterministic page fetches to a handful of internal/external hosts;
NO attack signal.
"""
from __future__ import annotations

from typing import Any

from tools.attackers.common import make_eve_record, rng_for


def generate(*, seed: int = 7, src_ip: str = "10.0.0.150",
             dst_ips: tuple[str, ...] = ("10.0.0.4", "93.184.216.34"),
             start_offset_s: float = 30.0, requests: int = 15) -> list[dict[str, Any]]:
    """Return `requests` benign http flow records."""
    rng = rng_for(seed, "benign_http")
    events: list[dict[str, Any]] = []
    for i in range(requests):
        events.append(make_eve_record(
            ts_offset=start_offset_s + i * rng.uniform(5, 25),
            src_ip=src_ip, dst_ip=rng.choice(dst_ips),
            src_port=rng.randint(40000, 60000), dst_port=443,
            proto="tcp", signal="", family=None,
            confidence=0.5, severity=1, signature_id=0))
    return events
