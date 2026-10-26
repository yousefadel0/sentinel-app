"""LIVE DataSources — tail Suricata eve.json and Zeek logs as sensors write them.

Unlike the M1 replay adapters these consume only NEW lines per ``fetch()``
and report ``source_type="live_file"``. Health is derived from facts, never
invented:

* file missing            -> ``down``
* file not written within ``stale_after_s`` -> ``degraded`` (sensor stalled
  or link silent — exactly the failure P4/§4 wants surfaced)
* otherwise               -> ``healthy``
* ``packet_drops`` comes from Suricata ``stats`` records
  (``stats.capture.kernel_drops``); None (N/A) for Zeek.
"""
from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from pathlib import Path

from sentinel.capture.adapters_file import zeek_adapter_for
from sentinel.capture.health import HealthSnapshot
from sentinel.capture.normalizer import normalize
from sentinel.capture.tail import OffsetStore, TailReader
from sentinel.capture.zeek_logs import _coerce
from sentinel.contracts.datasource import DataSource
from sentinel.detectors.dns import dns_signals
from sentinel.logging_setup import get_logger
from sentinel.models import Alert, AssetHint

log = get_logger("sentinel.capture.live")

DEFAULT_STALE_AFTER_S = 120.0


def _iso(epoch: float) -> str:
    return datetime.fromtimestamp(epoch, tz=timezone.utc).isoformat(
        timespec="seconds")


class _LiveBase(DataSource):
    def __init__(self, path: str | Path, *, state: OffsetStore | None,
                 start_at_end: bool, stale_after_s: float,
                 vlan: str | None,
                 critical_assets: dict[str, AssetHint] | None) -> None:
        self._path = Path(path)
        self._state = state or OffsetStore(None)
        self._tail = TailReader(self._path, state=self._state,
                                start_at_end=start_at_end)
        self._stale_after = float(stale_after_s)
        self._vlan = vlan
        self._assets = critical_assets or {}
        self._malformed = 0
        self._alerts = 0
        self._last_alert_ts: str | None = None
        self._drops: int | None = None

    def _record_alert(self, alert: Alert) -> None:
        self._alerts += 1
        self._last_alert_ts = alert.ts or None

    def health(self) -> dict:
        try:
            mtime = self._path.stat().st_mtime
        except OSError:
            mtime = None
        if mtime is None:
            status = "down"
        elif time.time() - mtime > self._stale_after:
            status = "degraded"
        else:
            status = "healthy"
        snap = HealthSnapshot(
            status=status,
            heartbeat_ts=_iso(mtime) if mtime is not None else None,
            packet_drops=self._drops,
            coverage_percent=None,
            last_alert_ts=self._last_alert_ts,
            source_type="live_file",
            malformed_lines_skipped=self._malformed,
        )
        out = snap.to_dict()
        out["heartbeat_basis"] = "file_mtime"
        out["rotations"] = self._tail.rotations
        out["file"] = self._path.name
        return out


class LiveEveDataSource(_LiveBase):
    """Tails a Suricata eve.json (JSON lines)."""

    name = "eve_json"

    def __init__(self, path: str | Path, *, state: OffsetStore | None = None,
                 start_at_end: bool = False,
                 stale_after_s: float = DEFAULT_STALE_AFTER_S,
                 vlan: str | None = None,
                 critical_assets: dict[str, AssetHint] | None = None,
                 signal_key: str | None = None) -> None:
        super().__init__(path, state=state, start_at_end=start_at_end,
                         stale_after_s=stale_after_s, vlan=vlan,
                         critical_assets=critical_assets)
        self._signal_key = signal_key

    def fetch(self) -> list[Alert]:
        lines = self._tail.read_new_lines()
        first = self._tail.line_no - len(lines)
        alerts: list[Alert] = []
        for i, line in enumerate(lines, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                raw = json.loads(line)
            except json.JSONDecodeError:
                self._malformed += 1
                continue
            if not isinstance(raw, dict):
                self._malformed += 1
                continue
            if raw.get("event_type") == "stats":
                kd = (((raw.get("stats") or {}).get("capture") or {})
                      .get("kernel_drops"))
                if isinstance(kd, int):
                    self._drops = max(self._drops or 0, kd)
                continue
            signals: tuple[str, ...] = ()
            if self._signal_key:
                sig = str(raw.get(self._signal_key) or "")
                if sig:
                    signals = (sig,)
            conf = 0.5
            if isinstance(raw.get("alert"), dict):
                try:
                    conf = float(raw["alert"].get("confidence", 0.5))
                except (TypeError, ValueError):
                    conf = 0.5
            if raw.get("event_type") == "dns" and isinstance(raw.get("dns"), dict):
                signals = (*signals, *dns_signals(raw["dns"].get("rrname")))
            alert = normalize(
                raw, adapter=self.name,
                ref=f"{self._path.name}#{first + i}",
                vlan=self._vlan,
                asset_hint=self._assets.get(str(raw.get("dest_ip", ""))),
                signals=signals, confidence_raw=conf)
            alerts.append(alert)
            self._record_alert(alert)
        return alerts


class LiveZeekDataSource(_LiveBase):
    """Tails one Zeek ASCII log, tracking #fields/#types across restarts."""

    def __init__(self, path: str | Path, *, state: OffsetStore | None = None,
                 start_at_end: bool = False,
                 stale_after_s: float = DEFAULT_STALE_AFTER_S,
                 vlan: str | None = None,
                 critical_assets: dict[str, AssetHint] | None = None) -> None:
        super().__init__(path, state=state, start_at_end=start_at_end,
                         stale_after_s=stale_after_s, vlan=vlan,
                         critical_assets=critical_assets)
        self._adapter = zeek_adapter_for(self._path)
        self._hdr_key = str(self._path.resolve()) + "::zeek_header"
        saved = self._state.get(self._hdr_key)
        self._fields: list[str] | None = saved.get("fields")
        self._types: list[str] = saved.get("types", [])

    @property
    def name(self):  # instance-level, mirrors ZeekLogFileDataSource
        return self._adapter

    def fetch(self) -> list[Alert]:
        lines = self._tail.read_new_lines()
        first = self._tail.line_no - len(lines)
        alerts: list[Alert] = []
        header_changed = False
        for i, line in enumerate(lines, start=1):
            stripped = line.rstrip("\n").rstrip("\t")
            if not stripped:
                continue
            if stripped.startswith("#"):
                directive = stripped.lstrip("#").strip()
                if directive.startswith("fields"):
                    self._fields = directive[len("fields"):].strip().split("\t")
                    header_changed = True
                elif directive.startswith("types"):
                    self._types = directive[len("types"):].strip().split("\t")
                    header_changed = True
                continue
            if self._fields is None:
                self._malformed += 1
                continue
            cells = stripped.split("\t")
            if len(cells) != len(self._fields):
                self._malformed += 1
                continue
            try:
                row = {n: _coerce(c, t) for n, c, t in zip(
                    self._fields, cells,
                    self._types or ["string"] * len(self._fields))}
            except ValueError:
                self._malformed += 1
                continue
            dst = str(row.get("id.resp_h", "") or "")
            # Zeek `ts` is epoch seconds; Alert.ts must be ISO-8601.
            ts = row.get("ts")
            if isinstance(ts, str):
                try:
                    row["ts"] = _iso(float(ts))
                except ValueError:
                    pass
            elif isinstance(ts, (int, float)):
                row["ts"] = _iso(float(ts))
            alert = normalize(
                row, adapter=self._adapter,
                ref=f"{self._path.name}#{first + i}",
                vlan=self._vlan, asset_hint=self._assets.get(dst),
                confidence_raw=0.5,
                signals=(f"zeek_{self._path.stem}",
                         *dns_signals(row.get("query"))))
            alerts.append(alert)
            self._record_alert(alert)
        if header_changed:
            self._state.put(self._hdr_key, {"fields": self._fields,
                                            "types": self._types})
        return alerts
