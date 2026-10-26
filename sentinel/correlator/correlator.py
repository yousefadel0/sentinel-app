"""Alerts -> incidents (M2).

An incident is ONE attack story between two endpoints: alerts sharing the
same (src_ip, dst_ip) pair merge into a single incident ACROSS signal
families — scan -> auth_fail_burst from one attacker against one target is
one escalating thread, not two SOC pages. The per-alert signals[] list
carries the family detail forward to M3 scoring untouched.

Chain semantics (operator-decided, test-pinned):
  * alerts are processed in ts order;
  * a chain continues while each INTER-ARRIVAL gap (consecutive alert ts
    difference) stays <= DEFAULT_CORRELATION_WINDOW_S measured from the
    LAST alert already in the chain — never "everything within N minutes
    of the first";
  * a single silent gap > window SPLITS the chain into a new incident.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Iterable

from sentinel.models import Alert
from sentinel.timeutil import parse_iso

DEFAULT_CORRELATION_WINDOW_S = 900  # 15 min; config wiring deferred to M6 (A1)


def _parse_ts(iso: str) -> datetime:
    """Parse an Alert.ts ISO-8601 string into an aware UTC datetime."""
    return parse_iso(iso)


@dataclass(frozen=True)
class Incident:
    """One merged attack story between two endpoints (immutable)."""

    incident_id: str
    src_ip: str
    dst_ip: str
    alerts: tuple[Alert, ...]          # ts-sorted members of this chain
    first_ts: str                      # ISO-8601 of earliest member
    last_ts: str                       # ISO-8601 of latest member
    signals: tuple[str, ...]           # union across members, order-stable


class Correlator:
    """Deterministic gap-chain correlator over the unified Alert model."""

    def __init__(self, window_s: int = DEFAULT_CORRELATION_WINDOW_S) -> None:
        if window_s <= 0:
            raise ValueError(f"window_s must be > 0, got {window_s}")
        self._window_s = window_s

    @property
    def window_s(self) -> int:
        return self._window_s

    def correlate(self, alerts: Iterable[Alert]) -> list[Incident]:
        """Merge alerts into incidents; returns them in first-seen order.

        Deterministic: input order never matters (ts-sort inside), equal
        timestamps keep a stable secondary order by alert_id.
        """
        ordered = sorted(alerts, key=lambda a: (_parse_ts(a.ts), a.alert_id))
        incidents: list[Incident] = []
        group: list[Alert] = []

        def flush() -> None:
            if not group:
                return
            signals: list[str] = []
            for a in group:
                for s in a.signals:
                    if s not in signals:
                        signals.append(s)
            incidents.append(
                Incident(
                    incident_id="inc-" + str(uuid.uuid5(
                        uuid.NAMESPACE_URL,
                        "|".join(a.alert_id for a in group))),
                    src_ip=group[0].src_ip,
                    dst_ip=group[0].dst_ip,
                    alerts=tuple(group),
                    first_ts=group[0].ts,
                    last_ts=group[-1].ts,
                    signals=tuple(signals),
                )
            )

        for alert in ordered:
            if (
                group
                and (alert.src_ip != group[0].src_ip or alert.dst_ip != group[0].dst_ip)
            ):
                flush()
                group = []
            elif group:
                gap = (_parse_ts(alert.ts) - _parse_ts(group[-1].ts)).total_seconds()
                if gap > self._window_s:
                    flush()
                    group = []
            group.append(alert)
        flush()
        return incidents
