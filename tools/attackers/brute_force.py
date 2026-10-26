"""SSH brute-force generator — deterministic eve records (M6, D6).

Emits a burst of failed SSH auth alerts from one source against one
asset; carries the ``auth_fail_burst`` signal → BRUTE_FORCE playbook.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from tools.attackers.common import SIGNAL_FAMILIES, make_eve_record, rng_for


def generate(*, seed: int = 42, src_ip: str = "198.51.100.77",
             dst_ip: str = "10.0.0.4", start_offset_s: float = 600.0,
             attempts: int = 25) -> list[dict[str, Any]]:
    """Return `attempts` failed-login alerts, ~2s apart."""
    rng = rng_for(seed, "brute_force")
    signal, sev = SIGNAL_FAMILIES["auth_fail_burst"]
    events: list[dict[str, Any]] = []
    for i in range(attempts):
        events.append(make_eve_record(
            ts_offset=start_offset_s + i * 2.0,
            src_ip=src_ip, dst_ip=dst_ip,
            src_port=rng.randint(40000, 60000), dst_port=22,
            proto="tcp", signal=signal, family="brute_force",
            confidence=round(0.85 + rng.random() * 0.1, 3),
            severity=sev, signature_id=2001219))
    return events
