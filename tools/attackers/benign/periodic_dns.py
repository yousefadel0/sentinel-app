"""Benign periodic DNS generator (Q2) — normal resolver lookups.

Regular short-label A queries to the site resolver; deliberately
periodic so it stresses the beacon detector's FP boundary without
carrying any attack signal.
"""
from __future__ import annotations

from typing import Any

from tools.attackers.common import make_eve_record


def generate(*, seed: int = 7, src_ip: str = "10.0.0.150",
             dst_ip: str = "10.0.0.5", start_offset_s: float = 45.0,
             lookups: int = 20, period_s: float = 30.0) -> list[dict[str, Any]]:
    """Return `lookups` benign dns flow records."""
    names = ["intranet", "gitlab", "wiki", "mail", "time"]
    events: list[dict[str, Any]] = []
    for i in range(lookups):
        rec = make_eve_record(
            ts_offset=start_offset_s + i * period_s,
            src_ip=src_ip, dst_ip=dst_ip,
            src_port=40000 + (i % 500), dst_port=53,
            proto="udp", signal="", family=None,
            confidence=0.5, severity=1, signature_id=0)
        rec["dns"] = {"type": "A",
                      "qtype_name": f"{names[i % len(names)]}.corp.example"}
        events.append(rec)
    return events
