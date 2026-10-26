"""Per-interface capture health (§4 DataSource.health contract).

Tracks heartbeat_ts, packet_drops and a coverage_percent STUB computed
against the asset inventory (site.critical_assets). Live sensors feed real
drop counters; file/replay adapters report HONEST documented-zero/N-A
values with an explicit ``source_type`` marker — never fabricated
live-looking numbers.
"""
from __future__ import annotations

import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any


def _now_iso() -> str:
    return datetime.now(tz=timezone.utc).isoformat(timespec="seconds")


@dataclass
class HealthSnapshot:
    """One interface's health state — shape of DataSource.health() output."""

    status: str = "down"                    # healthy | degraded | down
    heartbeat_ts: str | None = None         # iso8601 or None when never seen
    packet_drops: int | None = None         # None => N/A (honest for replay)
    coverage_percent: float | None = None   # stub vs asset inventory
    last_alert_ts: str | None = None
    source_type: str = "live"               # live | file_replay (folded item 2/3)
    malformed_lines_skipped: int = 0        # parser skips, surfaced via health()

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class CaptureHealthTracker:
    """Aggregates per-interface health; one tracker instance per interface.

    The M7 ops UI and the internal health alarm consume these snapshots;
    nothing here ever invents numbers that no sensor reported.
    """

    interface: str
    stale_after_seconds: float = 30.0
    _drops_seen: int = 0
    _alerts_seen: int = 0
    _malformed_seen: int = 0
    _last_heartbeat: str | None = None
    _last_alert: str | None = None
    _monotonic_last_seen: float = field(default_factory=time.monotonic)
    _inventory_size: int = 0

    # ---- inputs -------------------------------------------------------

    def record_heartbeat(self, *, ts: str | None = None,
                         drops: int | None = None) -> None:
        """Record a liveness signal from the sensor (ts=iso8601 or now)."""
        self._last_heartbeat = ts or _now_iso()
        if drops is not None:
            self._drops_seen = max(self._drops_seen, drops)
        self._monotonic_last_seen = time.monotonic()

    def record_drops(self, count: int) -> None:
        """Sensor-reported cumulative packet-drop counter."""
        self._drops_seen = max(self._drops_seen, int(count))

    def record_malformed(self, count_delta: int = 1) -> None:
        """Parser skipped malformed input; surfaced via health() (folded item 2)."""
        self._malformed_seen += int(count_delta)

    def record_alert(self, *, ts: str | None = None) -> None:
        self._alerts_seen += 1
        self._last_alert = ts or _now_iso()

    def set_inventory_size(self, n_critical_assets: int) -> None:
        """Coverage stub denominator = asset inventory size (§10-M1)."""
        self._inventory_size = max(0, int(n_critical_assets))

    def note_asset_seen(self) -> None:
        """Stub hook: an event touched an inventoried asset (M2 refines)."""
        self._assets_touched = getattr(self, "_assets_touched", 0) + 1

    # ---- outputs ------------------------------------------------------

    def snapshot(self, *, source_type: str = "live") -> HealthSnapshot:
        """Current health per the §4 contract shape.

        status: healthy when heartbeat fresh; degraded when stale but seen;
        down when never seen. Callers pass ``source_type="file_replay"`` for
        replay adapters so consumers can interpret N/A counters honestly.
        """
        age = time.monotonic() - self._monotonic_last_seen
        if self._last_heartbeat is None:
            status = "down"
        elif age > self.stale_after_seconds:
            status = "degraded"
        else:
            status = "healthy"

        coverage: float | None = None
        if self._inventory_size:
            touched = getattr(self, "_assets_touched", 0)
            coverage = round(min(100.0, 100.0 * touched / self._inventory_size), 2)

        return HealthSnapshot(
            status=status,
            heartbeat_ts=self._last_heartbeat,
            packet_drops=self._drops_seen or None,
            coverage_percent=coverage,
            last_alert_ts=self._last_alert,
            source_type=source_type,
            malformed_lines_skipped=self._malformed_seen,
        )
