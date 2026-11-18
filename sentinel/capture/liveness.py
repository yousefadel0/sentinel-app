"""Flow liveness — "is this address still talking right now?" from real flows.

The decision chain needs to know whether the target of an action is still
active before anything is enforced (§3.1 liveness row). This tracker answers
that from evidence the sensors already produce: every Zeek ``conn.log`` row
and Suricata flow/alert record carries src/dst addresses and a timestamp.

    alive   -> the address appeared in a flow within ``window_s``
    stale   -> it appeared before, but not within ``window_s``
    unknown -> it never appeared since the daemon started

Nothing is invented: an address the sensors never saw is "unknown", and the
engine/executor treat that as "no proof" (escalate, never auto-act).
"""
from __future__ import annotations

import threading
from collections import OrderedDict, deque
from datetime import datetime, timezone
from typing import Callable, Iterable

from sentinel.timeutil import parse_iso

#: How recent a flow must be to count as "still active".
DEFAULT_WINDOW_S = 600
#: Upper bound on remembered addresses (oldest are evicted first).
MAX_TRACKED = 200_000
#: Conversation memory for incident evidence ("who talked to whom").
FLOWS_PER_IP = 40
MAX_FLOW_IPS = 20_000


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class FlowLiveness:
    """Thread-safe last-seen map; callable as an engine/executor liveness check."""

    def __init__(self, *, window_s: int = DEFAULT_WINDOW_S,
                 clock: Callable[[], datetime] = _utcnow,
                 max_tracked: int = MAX_TRACKED) -> None:
        self._window = float(window_s)
        self._clock = clock
        self._max = max_tracked
        self._seen: dict[str, float] = {}
        self._flows: OrderedDict[str, deque] = OrderedDict()
        self._lock = threading.Lock()

    def bind_clock(self, clock: Callable[[], datetime]) -> None:
        """Share the daemon's clock so 'recent' means the same thing everywhere."""
        self._clock = clock

    def observe(self, alerts: Iterable) -> None:
        """Record last-seen time for every src/dst address in ``alerts``."""
        with self._lock:
            for a in alerts:
                try:
                    t = parse_iso(a.ts).timestamp()
                except (ValueError, TypeError, AttributeError):
                    continue
                src, dst = getattr(a, "src_ip", ""), getattr(a, "dst_ip", "")
                for ip in (src, dst):
                    if ip and t > self._seen.get(ip, 0.0):
                        self._seen[ip] = t
                self._remember(a, t, src, dst)
            if len(self._seen) > self._max:
                for ip, _ in sorted(self._seen.items(),
                                    key=lambda kv: kv[1])[: len(self._seen) - self._max]:
                    del self._seen[ip]

    def _remember(self, a, t: float, src: str, dst: str) -> None:
        source = getattr(getattr(a, "source", None), "adapter", "")
        meta = getattr(a, "meta", None)
        row = {"ts": t, "src": src, "sport": getattr(a, "src_port", 0),
               "dst": dst, "dport": getattr(a, "dst_port", 0),
               "proto": getattr(a, "protocol", ""), "source": source,
               "bytes": getattr(meta, "byte_count", None),
               "what": getattr(meta, "label", None)}
        for ip in {src, dst} - {""}:
            q = self._flows.get(ip)
            if q is None:
                q = self._flows[ip] = deque(maxlen=FLOWS_PER_IP)
            else:
                self._flows.move_to_end(ip)
            q.append(row)
        while len(self._flows) > MAX_FLOW_IPS:
            self._flows.popitem(last=False)

    def recent_flows(self, ip: str, limit: int = FLOWS_PER_IP) -> list[dict]:
        """Most recent records involving ``ip`` (newest last), metadata only."""
        with self._lock:
            q = self._flows.get(ip)
            return list(q)[-limit:] if q else []

    def state(self, ip: str) -> str:
        with self._lock:
            t = self._seen.get(ip)
        if t is None:
            return "unknown"
        age = self._clock().timestamp() - t
        return "alive" if age <= self._window else "stale"

    def __call__(self, ctx: dict) -> str:
        """Liveness of the incident's acting party (the source, else the target)."""
        ip = ctx.get("src_ip") or ctx.get("dst_ip") or ""
        return self.state(str(ip)) if ip else "unknown"

    def snapshot(self) -> dict:
        with self._lock:
            return {"tracked": len(self._seen), "window_s": int(self._window)}
