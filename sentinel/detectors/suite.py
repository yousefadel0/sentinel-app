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

Performance: events are indexed per key (source, destination, channel,
DNS pair) and each cycle re-evaluates ONLY the keys that received new
events, so cycle cost scales with traffic in the last second rather than
with the size of the whole window.
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

_GC_EVERY_S = 10.0


@dataclass(frozen=True)
class DetectorConfig:
    window_s: int = 300
    beacon_window_s: int = 1800
    scan_min_targets: int = 20        # distinct (dst, dport) from one src
    scan_burst_s: int = 30            # ...within this short burst window
    brute_min_conns: int = 15         # conns src->dst:port on auth ports
    ddos_min_sources: int = 50        # distinct sources -> one dst
    ddos_min_conns: int = 500
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


def _trim(dq: deque, lo: float) -> int:
    """Drop events older than ``lo`` from the left; returns how many."""
    n = 0
    while dq and dq[0].t < lo:
        dq.popleft()
        n += 1
    return n


@dataclass
class DetectorSuite:
    cfg: DetectorConfig = field(default_factory=DetectorConfig)

    def __post_init__(self) -> None:
        self._by_src: dict[str, deque] = defaultdict(deque)
        self._by_dst: dict[str, deque] = defaultdict(deque)
        self._chan: dict[tuple[str, str, int], deque] = defaultdict(deque)
        self._dns: dict[tuple[str, str], deque] = defaultdict(deque)
        self._dirty_src: set = set()
        self._dirty_dst: set = set()
        self._dirty_chan: set = set()
        self._dirty_dns: set = set()
        self._latest = 0.0
        self._n = 0
        self._last_gc = 0.0
        self._emitted: dict[tuple[str, str, str], tuple[int, float]] = {}

    @property
    def tracked_events(self) -> int:
        return self._n

    # -- ingestion ------------------------------------------------------- #

    def ingest(self, alerts) -> None:
        for a in alerts:
            sigs = set(a.signals)
            is_flow = bool(sigs & _FLOW_MARKERS)
            is_dns = SUSPICIOUS_DNS in sigs
            if not (is_flow or is_dns):
                continue
            try:
                t = _epoch(a.ts)
            except ValueError:
                continue
            ev = _Ev(t, a)
            self._latest = max(self._latest, t)
            if is_flow:
                self._by_src[a.src_ip].append(ev)
                self._dirty_src.add(a.src_ip)
                self._by_dst[a.dst_ip].append(ev)
                self._dirty_dst.add(a.dst_ip)
                self._n += 2
                if a.dst_port not in BEACON_IGNORE_PORTS:
                    key = (a.src_ip, a.dst_ip, a.dst_port)
                    self._chan[key].append(ev)
                    self._dirty_chan.add(key)
                    self._n += 1
            if is_dns:
                key2 = (a.src_ip, a.dst_ip)
                self._dns[key2].append(ev)
                self._dirty_dns.add(key2)
                self._n += 1
        if (self._latest - self._last_gc >= _GC_EVERY_S
                or self._n > self.cfg.max_tracked):
            self._gc()

    def _gc(self) -> None:
        """Trim every index to its own window; shed oldest data if over cap."""
        self._last_gc = self._latest
        shrink = 1.0
        while True:
            for index, window in ((self._by_src, self.cfg.window_s),
                                  (self._by_dst, self.cfg.window_s),
                                  (self._dns, self.cfg.window_s),
                                  (self._chan, self.cfg.beacon_window_s)):
                lo = self._latest - window * shrink
                for key in list(index):
                    dq = index[key]
                    self._n -= _trim(dq, lo)
                    if not dq:
                        del index[key]
            if self._n <= self.cfg.max_tracked or shrink < 0.05:
                return
            shrink /= 2                  # still over budget: keep less history

    # -- detection ------------------------------------------------------- #

    def detect(self) -> list[Alert]:
        # (signal, src, dst, count, threshold, members)
        found: list[tuple[str, str, str, int, int, list[_Ev]]] = []
        win_lo = self._latest - self.cfg.window_s

        for src in self._dirty_src:
            dq = self._by_src.get(src)
            if dq is None:
                continue
            self._n -= _trim(dq, win_lo)
            evs = [e for e in dq if e.t >= win_lo]
            if not evs:
                continue
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

        for dst in self._dirty_dst:
            dq = self._by_dst.get(dst)
            if dq is None:
                continue
            self._n -= _trim(dq, win_lo)
            if len(dq) < self.cfg.ddos_min_conns:
                continue
            evs = [e for e in dq if e.t >= win_lo]
            srcs: dict[str, int] = defaultdict(int)
            for e in evs:
                srcs[e.alert.src_ip] += 1
            if (len(srcs) >= self.cfg.ddos_min_sources
                    and len(evs) >= self.cfg.ddos_min_conns):
                top = max(srcs, key=lambda s: (srcs[s], s))
                found.append(("volume_spike", top, dst, len(evs),
                              self.cfg.ddos_min_conns, evs))

        beacon_lo = self._latest - self.cfg.beacon_window_s
        for key in self._dirty_chan:
            dq = self._chan.get(key)
            if dq is None:
                continue
            self._n -= _trim(dq, beacon_lo)
            if len(dq) < self.cfg.beacon_min_events:
                continue
            evs = [e for e in dq if e.t >= beacon_lo]
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
                found.append(("beacon_periodic", key[0], key[1], len(evs),
                              self.cfg.beacon_min_events, evs))

        for key in self._dirty_dns:
            dq = self._dns.get(key)
            if dq is None:
                continue
            self._n -= _trim(dq, win_lo)
            evs = [e for e in dq if e.t >= win_lo]
            if len(evs) >= self.cfg.dns_min_flagged:
                found.append(("dns_tunneling", key[0], key[1], len(evs),
                              self.cfg.dns_min_flagged, evs))

        self._dirty_src.clear()
        self._dirty_dst.clear()
        self._dirty_chan.clear()
        self._dirty_dns.clear()
        return self._emit(found)

    def _burst_targets(self, evs: list[_Ev]) -> set[tuple[str, int]]:
        """Largest distinct-(dst, dport) set inside any scan_burst_s window.

        Scans fan out fast; ordinary clients touch many servers only slowly,
        so a short burst window separates the two.
        """
        if len({(e.alert.dst_ip, e.alert.dst_port) for e in evs}) \
                < self.cfg.scan_min_targets:
            return set()                  # cannot reach the bar at all
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
        for signal, src, dst, count, threshold, members in found:
            key = (signal, src, dst)
            prev = self._emitted.get(key)
            if (prev is not None
                    and self._latest - prev[1] < self.cfg.beacon_window_s
                    and count < 2 * prev[0]):
                continue
            self._emitted[key] = (count, self._latest)
            out.append(self._alert(signal, src, dst, count, threshold, members))
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
