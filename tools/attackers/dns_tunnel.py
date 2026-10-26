"""DNS-tunneling generator — deterministic eve records (M6, D6).

Emits long-TXT DNS queries with high-entropy subdomains from one host;
carries the ``dns_tunneling`` signal → DNS_TUNNELING playbook.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from tools.attackers.common import SIGNAL_FAMILIES, make_eve_record, rng_for


def generate(*, seed: int = 42, src_ip: str = "10.0.0.5",
             dst_ip: str = "198.51.100.53", start_offset_s: float = 1800.0,
             queries: int = 20) -> list[dict[str, Any]]:
    """Return `queries` suspicious DNS alerts, ~3s apart."""
    rng = rng_for(seed, "dns_tunnel")
    signal, sev = SIGNAL_FAMILIES["dns_tunneling"]
    events: list[dict[str, Any]] = []
    for i in range(queries):
        label = "".join(rng.choice("abcdefghijklmnopqrstuvwxyz0123456789")
                        for _ in range(40))
        events.append(make_eve_record(
            ts_offset=start_offset_s + i * 3.0,
            src_ip=src_ip, dst_ip=dst_ip,
            src_port=rng.randint(40000, 60000), dst_port=53,
            proto="udp", signal=signal, family="dns_tunneling",
            confidence=round(0.7 + rng.random() * 0.1, 3),
            severity=sev, signature_id=2023215))
        events[-1]["dns"] = {"type": "TXT",
                             "qtype_name": f"{label}.tunnel.example"}
    return events
