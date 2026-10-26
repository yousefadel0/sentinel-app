"""ABC #1 — DataSource adapter contract (§4).

All ingestion integrations implement this interface. Core never knows vendor
details (P2): Suricata eve.json streams, Zeek logs, file/replay fixtures and
future cloud-mirror adapters are all just DataSources.

Implementations MUST NOT return raw payloads — hashes/summaries only.
"""
from __future__ import annotations

import abc
from typing import ClassVar

from sentinel.models import Alert

__docstring_contract__ = (
    "fetch() -> list[Alert]; health() -> HealthStatus "
    "{status: healthy|degraded|down, heartbeat_ts, packet_drops, "
    "coverage_percent, last_alert_ts}"
)


class DataSource(abc.ABC):
    """Typed interface every capture/ingestion adapter must implement.

    Contract (§4 Adapter contract ABC #1):

    * ``fetch()`` drains currently-available events and returns a list of
      unified :class:`sentinel.models.Alert` objects. Must be non-blocking at
      the scale of one poll cycle; empty list means "nothing new", never an
      error condition by itself.

    * ``health()`` reports per-interface capture health used by the capture
      health monitor (heartbeat, packet-drop counters, coverage %). A sensor
      that stops producing alerts is NOT necessarily healthy — heartbeat and
      drop counters exist precisely to expose that.

    * Implementations must never raise on transient upstream faults from
      ``fetch()``; report them via ``health().status == "degraded"|"down"``
      instead (P4 degrades gracefully).
    """

    #: stable adapter identifier for audit provenance (e.g. "eve_json")
    name: ClassVar[str] = "datasource"

    @abc.abstractmethod
    def fetch(self) -> list[Alert]:
        """Return newly available events as unified Alerts (may be empty)."""
        raise NotImplementedError

    @abc.abstractmethod
    def health(self) -> dict:
        """Return health snapshot:

        {status: 'healthy'|'degraded'|'down', heartbeat_ts: iso8601|None,
         packet_drops: int, coverage_percent: float 0..100,
         last_alert_ts: iso8601|None}
        """
        raise NotImplementedError
