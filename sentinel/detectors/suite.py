"""Behavioral detector suite — wire flows in, attack-signal alerts out.

Covers the five v1 attack families (Project.md §2) from Zeek ``conn``/eve
``flow`` records and DNS-derived tokens. Every detector is a pure function
of the event-time window (no wall clock): replaying the same capture yields
the same alerts, which is what makes the evaluation harness meaningful.

Emitted alerts are Tier B (wire + behavioral, §3) carrying exactly one
signal the Decision Engine already understands (``scan``,
``auth_fail_burst``, ``volume_spike``, ``beacon_periodic``,
``dns_tunneling``). A story is re-emitted only when it escalates (count
doubled), so a long attack does not flood the audit store.
"""
from __future__ import annotations

import statistics
import uuid
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timezone

from sentinel.correlator.correlator import _parse_ts
from sentinel.decision.models import SIGNAL_TO_ATTACK
from sentinel.detectors.dns import SUSPICIOUS_DNS
from sentinel.models import (Alert, AlertMeta, AssetHint, ConfidenceTier,
                             SourceRef)

#: Signals that make a raw alert incident-worthy on its own (Suricata
#: signature hits and anything already carrying a known attack signal).
_ATTACK_SIGNALS = frozenset(s for s, _ in SIGNAL_TO_ATTACK)
_FLOW_MARKERS = frozenset({"zeek_conn", "flow_record"})

BRUTE_PORTS = frozenset({21, 22, 23, 1433, 3306, 3389, 5900, 5985})
BEACON_IGNORE_PORTS = frozenset({53, 123, 5353, 67, 68, 137, 138})


@dataclass(frozen=True)
class DetectorConfig:
    window_s: int = 300
    beacon_window_s: int = 1800
    scan_min_targets: int = 20        # distinct (dst, dport) from one src
    brute_min_conns: int = 15         # conns src->dst:port on auth ports
    ddos_min_sources: int = 50        # distinct sources -> one dst
    ddos_min_conns: int = 500
    scan_burst_s: int = 30            # ...within this short burst window
    beacon_min_events: int = 12
    beacon_tolerance: float = 0.20    # gap within +-20% of the median gap
    beacon_min_fraction: float = 0.90  # share of gaps that must be regular
    beacon_min_interval_s: float = 5.0
    dns_min_flagged: int = 15         # suspicious qnames src -> resolver
    max_tracked: int = 200_000


def is_incident_worthy(alert: Alert) -> bool:
    """Should this alert enter correlation (vs. only feed the detectors)?"""
    sigs = set(alert.signals)
    return bool(sigs & _ATTACK_SIGNALS) or "signature_hit" in sigs


@dataclass
class _Ev:
    t: float
    alert: Alert


def _epoch(ts: str) -> float:
    return _parse_ts(ts).timestamp()


def _iso(epoch: float) -> str:
    return datetime.fromtimestamp(epoch, tz=timezone.utc).isoformat()


@dataclass
class DetectorSuite:
    cfg: DetectorConfig = field(default_factory=DetectorConfig)

    def __post_init__(self) -> None:
        self._events: deque[_Ev] = deque()
        self._latest = 0.0
        self._emitted: dict[tuple[str, str, str], int] = {}
        self._dirty = False

    # -- ingestion ------------------------------------------------------- #

    def ingest(self, alerts) -> None:
        for a in alerts:
            sigs = set(a.signals)
            if not (sigs & _FLOW_MARKERS or SUSPICIOUS_DNS in sigs):
                continue
            try:
                t = _epoch(a.ts)
            except ValueError:
                continue
            self._events.append(_Ev(t, a))
            self._dirty = True
            self._latest = max(self._latest, t)
        horizon = self._latest - max(self.cfg.window_s, self.cfg.beacon_window_s)
        while self._events and (self._events[0].t < horizon
                                or len(self._events) > self.cfg.max_tracked):
            self._events.popleft()

    def _within(self, seconds: int):
        lo = self._latest - seconds
        return [e for e in self._events if e.t >= lo]

    # -- detection ------------------------------------------------------- #

    def detect(self) -> list[Alert]:
        if not self._dirty:                 # nothing new since last pass
            return []
        self._dirty = False
        # (signal, src, dst, count, threshold, members)
        found: list[tuple[str, str, str, int, int, list[_Ev]]] = []
        recent = self._within(self.cfg.window_s)
        flows = [e for e in recent if set(e.alert.signals) & _FLOW_MARKERS]

        by_src: dict[str, list[_Ev]] = defaultdict(list)
        for e in flows:
            by_src[e.alert.src_ip].append(e)
        for src, evs in by_src.items():
            targets = self._burst_targets(evs)
            if len(targets) >= self.cfg.scan_min_targets:
                per_dst: dict[str, int] = defaultdict(int)
                for d, _ in targets:
                    per_dst[d] += 1
                top = max(per_dst, key=lambda d: (per_dst[d], d))
                found.append(("scan", src, top, len(targets),
                              self.cfg.scan_min_targets, evs))
            pair: dict[tuple[str, int], list[_Ev]] = defaultdict(list)
            for e in evs:
                if e.alert.dst_port in BRUTE_PORTS:
                    pair[(e.alert.dst_ip, e.alert.dst_port)].append(e)
            for (dst, _port), pe in pair.items():
                if len(pe) >= self.cfg.brute_min_conns:
                    found.append(("auth_fail_burst", src, dst, len(pe),
                                  self.cfg.brute_min_conns, pe))

        by_dst: dict[str, list[_Ev]] = defaultdict(list)
        for e in flows:
            by_dst[e.alert.dst_ip].append(e)
        for dst, evs in by_dst.items():
            srcs: dict[str, int] = defaultdict(int)
            for e in evs:
                srcs[e.alert.src_ip] += 1
            if (len(srcs) >= self.cfg.ddos_min_sources
                    and len(evs) >= self.cfg.ddos_min_conns):
                top = max(srcs, key=lambda s: (srcs[s], s))
                found.append(("volume_spike", top, dst, len(evs),
                              self.cfg.ddos_min_conns, evs))

        beacon_flows = [e for e in self._within(self.cfg.beacon_window_s)
                        if set(e.alert.signals) & _FLOW_MARKERS
                        and e.alert.dst_port not in BEACON_IGNORE_PORTS]
        chans: dict[tuple[str, str, int], list[_Ev]] = defaultdict(list)
        for e in beacon_flows:
            chans[(e.alert.src_ip, e.alert.dst_ip, e.alert.dst_port)].append(e)
        for (src, dst, _p), evs in chans.items():
            if len(evs) < self.cfg.beacon_min_events:
                continue
            ts = sorted(e.t for e in evs)
            gaps = [b - a for a, b in zip(ts, ts[1:])]
            med = statistics.median(gaps)
            if med < self.cfg.beacon_min_interval_s:
                continue
            regular = sum(1 for g in gaps
                          if abs(g - med) <= self.cfg.beacon_tolerance * med)
            if regular / len(gaps) >= self.cfg.beacon_min_fraction:
                found.append(("beacon_periodic", src, dst, len(evs),
                              self.cfg.beacon_min_events, evs))

        dns: dict[tuple[str, str], list[_Ev]] = defaultdict(list)
        for e in recent:
            if SUSPICIOUS_DNS in e.alert.signals:
                dns[(e.alert.src_ip, e.alert.dst_ip)].append(e)
        for (src, dst), evs in dns.items():
            if len(evs) >= self.cfg.dns_min_flagged:
                found.append(("dns_tunneling", src, dst, len(evs),
                              self.cfg.dns_min_flagged, evs))

        return self._emit(found)

    def _burst_targets(self, evs: list[_Ev]) -> set[tuple[str, int]]:
        """Largest distinct-(dst, dport) set inside any scan_burst_s window.

        Scans fan out fast; ordinary clients touch many servers only slowly,
        so a short burst window separates the two.
        """
        evs = sorted(evs, key=lambda e: e.t)
        best: set[tuple[str, int]] = set()
        lo = 0
        for hi in range(len(evs)):
            while evs[hi].t - evs[lo].t > self.cfg.scan_burst_s:
                lo += 1
            window = {(e.alert.dst_ip, e.alert.dst_port) for e in evs[lo:hi + 1]}
            if len(window) > len(best):
                best = window
        return best

    def _emit(self, found) -> list[Alert]:
        out: list[Alert] = []
        live_keys = set()
        for signal, src, dst, count, threshold, members in found:
            key = (signal, src, dst)
            live_keys.add(key)
            prev = self._emitted.get(key)
            if prev is not None and count < 2 * prev:
                continue
            self._emitted[key] = count
            out.append(self._alert(signal, src, dst, count, threshold, members))
        self._emitted = {k: v for k, v in self._emitted.items()
                         if k in live_keys}
        return out

    @staticmethod
    def _alert(signal, src, dst, count, threshold, members) -> Alert:
        last = max(members, key=lambda e: e.t)
        strength = min(1.0, max(0.0, count / threshold - 1.0))
        hint = next((e.alert.asset_hint for e in members
                     if e.alert.asset_hint and e.alert.asset_hint.criticality),
                    AssetHint())
        sample = last.alert
        return Alert(
            alert_id=str(uuid.uuid5(uuid.NAMESPACE_URL,
                                    f"{signal}|{src}|{dst}|{count}|{last.t}")),
            ts=_iso(last.t),
            source=SourceRef(adapter="behavioral",
                             ref=f"detector:{signal}:{src}>{dst}"),
            src_ip=src, dst_ip=dst,
            src_port=0, dst_port=sample.dst_port if signal != "scan" else 0,
            protocol=sample.protocol, vlan=sample.vlan,
            asset_hint=hint, signals=(signal,),
            confidence_raw=round(0.85 + 0.12 * strength, 4),
            confidence_tier=ConfidenceTier.B,
            meta=AlertMeta(packet_count=None, byte_count=None,
                           duration_seconds=None, raw_payload_hash=None),
        )
