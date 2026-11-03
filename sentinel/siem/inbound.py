"""Inbound Wazuh identity/auth evidence — Tier C by doctrine (§3).

Tails Wazuh's ``alerts.json`` (one JSON object per line; the forwarder or a
shared volume provides it, so Sentinel needs no SIEM credentials). Only
authentication-failure rule groups become alerts, carrying the existing
``auth_fail_burst`` signal. Tier C means the Decision Engine caps any such
story at notify/human — SIEM evidence alone can NEVER trigger an automated
action, and with no SIEM the wire loop is unaffected (P3).
"""
from __future__ import annotations

import ipaddress
import json
from pathlib import Path

from sentinel.capture.live import _LiveBase
from sentinel.capture.confidence import wazuh_confidence
from sentinel.capture.normalizer import normalize
from sentinel.capture.tail import OffsetStore
from sentinel.models import Alert

ADAPTER = "wazuh_inbound"
AUTH_GROUPS = frozenset({"authentication_failed", "authentication_failures",
                         "invalid_login", "win_authentication_failed",
                         "sshd_authentication_failed"})


def _ip(value) -> str | None:
    try:
        return str(ipaddress.ip_address(str(value)))
    except ValueError:
        return None


class WazuhAlertsFileDataSource(_LiveBase):
    name = ADAPTER

    def __init__(self, path: str | Path, *, state: OffsetStore | None = None,
                 start_at_end: bool = False, stale_after_s: float = 3600.0):
        super().__init__(path, state=state, start_at_end=start_at_end,
                         stale_after_s=stale_after_s, vlan=None,
                         critical_assets=None)

    def fetch(self) -> list[Alert]:
        lines = self._tail.read_new_lines()
        first = self._tail.line_no - len(lines)
        out: list[Alert] = []
        for i, line in enumerate(lines, start=1):
            try:
                ev = json.loads(line)
            except ValueError:
                self._malformed += 1
                continue
            rule = ev.get("rule") if isinstance(ev, dict) else None
            groups = set((rule or {}).get("groups") or [])
            if not groups & AUTH_GROUPS:
                continue
            data = ev.get("data") or {}
            src = _ip(data.get("srcip") or data.get("src_ip"))
            dst = _ip((ev.get("agent") or {}).get("ip"))
            if src is None or dst is None:
                self._malformed += 1
                continue
            raw = {"timestamp": ev.get("timestamp", ""), "src_ip": src,
                   "dest_ip": dst, "proto": "tcp",
                   "dest_port": int(data.get("dstport", 0) or 0)}
            alert = normalize(raw, adapter=ADAPTER,
                              ref=f"{self._path.name}#{first + i}",
                              signals=("auth_fail_burst",),
                              confidence_raw=wazuh_confidence(
                                  (rule or {}).get("level")))
            out.append(alert)
            self._record_alert(alert)
        return out
