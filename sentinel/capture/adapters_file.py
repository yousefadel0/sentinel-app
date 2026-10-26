"""File/replay DataSources — the first dev adapters (§10-M1).

HONEST health semantics (operator expectation): these are NOT live sensors.
* ``packet_drops`` is a documented ZERO (nothing was dropped because nothing
  was captured live) and ``source_type="file_replay"`` marks every snapshot
  so consumers never mistake replay for live capture.
* ``heartbeat_ts`` = fixture file mtime when the file exists on disk, else
  ingestion time (folded item 3) — documented here per contract.
* ``coverage_percent`` stays None (N/A) until an inventory-backed stub has
  something real to report; we do not fabricate percentages.

fetch() streams through the parsers — constant memory, malformed lines
skipped+counted, never crashing the loop.
"""
from __future__ import annotations

import os
from datetime import datetime, timezone
from pathlib import Path

from sentinel.capture.eve_parser import iter_eve
from sentinel.capture.health import CaptureHealthTracker
from sentinel.capture.normalizer import normalize
from sentinel.capture.zeek_logs import iter_zeek
from sentinel.contracts.datasource import DataSource
from sentinel.logging_setup import get_logger
from sentinel.models import Alert, AssetHint

log = get_logger("sentinel.capture.adapters_file")

#: Zeek log basename -> adapter provenance name (rides §4 "<future>" marker).
#: Bare canonical names ("conn.log"); a leading "zeek_" prefix is tolerated
#: so replay fixtures can be self-descriptive.
ZEEK_ADAPTERS: dict[str, str] = {
    "conn.log": "zeek_conn",
    "dns.log": "zeek_dns",
    "ssl.log": "zeek_ssl",
    "notice.log": "zeek_notice",
}


def zeek_adapter_for(path: Path) -> str:
    """Resolve adapter provenance from the log filename; '' when unknown."""
    base = path.name
    if base not in ZEEK_ADAPTERS and base.startswith("zeek_"):
        base = base[len("zeek_"):]
    return ZEEK_ADAPTERS.get(base, "")


def _mtime_or_now(path: Path) -> tuple[str, str]:
    """(iso8601 heartbeat, basis) from file mtime, else ingestion time."""
    try:
        stamp = path.stat().st_mtime
        basis = "file_mtime"
    except OSError:
        stamp = datetime.now(tz=timezone.utc).timestamp()
        basis = "ingestion_time"
    return (
        datetime.fromtimestamp(stamp, tz=timezone.utc).isoformat(timespec="seconds"),
        basis,
    )


class EveFileDataSource(DataSource):
    """Replays a Suricata eve.json (or .jsonl) fixture as Alerts.

    health() is honest per the class docstring; ``heartbeat_ts`` comes from
    the fixture's mtime when available, otherwise ingestion time.
    """

    name = "eve_json"

    def __init__(self, path: str | Path, *, vlan: str | None = None,
                 critical_assets: dict[str, AssetHint] | None = None,
                 signal_key: str | None = None) -> None:
        """``signal_key`` (M6): optional harness-private eve key whose value
        feeds normalize() as a base signal label (e.g. ``"sentinel_signal"``
        from the committed M6 generators). Default None keeps exact M1
        behavior — no other adapter semantics change."""
        self._path = Path(path)
        self._vlan = vlan
        self._assets = critical_assets or {}
        self._signal_key = signal_key
        self._tracker = CaptureHealthTracker(interface=self.name)
        self._malformed = 0

    # -- DataSource -----------------------------------------------------

    def fetch(self) -> list[Alert]:
        alerts: list[Alert] = []
        try:
            stream = iter_eve(self._path, on_malformed=self._tracker.record_malformed)
            for i, raw in enumerate(stream, start=1):
                ref = f"{self._path.name}#{i}"
                hint = self._assets.get(str(raw.get("dest_ip", "")))
                signals: tuple[str, ...] = ()
                if self._signal_key is not None:
                    sig = str(raw.get(self._signal_key) or "")
                    if sig:
                        signals = (sig,)
                alert = normalize(
                    raw,
                    adapter=self.name,
                    ref=ref,
                    vlan=self._vlan,
                    asset_hint=hint,
                    signals=signals,
                    confidence_raw=float(raw.get("alert", {}).get("confidence", 0.5))
                    if isinstance(raw.get("alert"), dict) else 0.5,
                )
                alerts.append(alert)
                self._tracker.record_alert(ts=alert.ts or None)
        except OSError:
            # P4 degrade gracefully: missing/unreadable fixture => empty,
            # health() reports down — never crash the capture loop.
            log.warning("eve_source_unreadable", path=str(self._path))
            return []
        return alerts

    def health(self) -> dict:
        heartbeat, basis = _mtime_or_now(self._path)
        snap = self._tracker.snapshot(source_type="file_replay")
        snap.heartbeat_ts = heartbeat
        snap.packet_drops = 0          # documented zero — see class docstring
        snap.status = "healthy" if self._path.exists() else "down"
        out = snap.to_dict()
        out["heartbeat_basis"] = basis  # folded item 3: explicit provenance
        return out


class ZeekLogFileDataSource(DataSource):
    """Replays one Zeek ASCII log (conn/dns/ssl/notice) as Alerts."""

    def __init__(self, path: str | Path, *, vlan: str | None = None,
                 critical_assets: dict[str, AssetHint] | None = None) -> None:
        self._path = Path(path)
        self._vlan = vlan
        self._assets = critical_assets or {}
        self._adapter = zeek_adapter_for(self._path)
        self._tracker = CaptureHealthTracker(interface=self._adapter or "zeek_unknown")

    @property
    def name(self):  # instance-level override; ClassVar default untouched
        return self._adapter

    def fetch(self) -> list[Alert]:
        alerts: list[Alert] = []
        try:
            stream = iter_zeek(self._path, on_malformed=self._tracker.record_malformed)
            for i, row in enumerate(stream, start=1):
                ref = f"{self._path.name}#{i}"
                dst = str(row.get("id.resp_h", "") or "")
                hint = self._assets.get(dst)
                alert = normalize(
                    row,
                    adapter=self._adapter,
                    ref=ref,
                    vlan=self._vlan,
                    asset_hint=hint,
                    confidence_raw=0.5,
                    signals=(f"zeek_{self._path.stem}",),
                )
                alerts.append(alert)
                self._tracker.record_alert(ts=alert.ts or None)
        except OSError:
            log.warning("zeek_source_unreadable", path=str(self._path))
            return []
        return alerts

    def health(self) -> dict:
        heartbeat, basis = _mtime_or_now(self._path)
        snap = self._tracker.snapshot(source_type="file_replay")
        snap.heartbeat_ts = heartbeat
        snap.packet_drops = 0          # documented zero — see EveFileDataSource
        snap.status = "healthy" if self._path.exists() else "down"
        out = snap.to_dict()
        out["heartbeat_basis"] = basis
        return out
