"""Sentinel live daemon — capture -> correlate -> decide -> audit (SHADOW only).

The loop is SHADOW-ALWAYS (G2/P5): every decision is a recommendation
persisted to the append-only audit store; nothing is ever executed here.
Actuation stays behind the validator/actuator path and explicit operator opt-in.

Streaming incident semantics: alerts accumulate in a rolling buffer; each
cycle the buffer is re-correlated and an incident story (keyed by
src/dst/first_ts) is (re)decided only when it ESCALATES — a new signal family
joins it, or its alert count has doubled since the last decision. That gives
second-level MTTD without writing a decision per alert.
"""
from __future__ import annotations

import json
import os
import threading
from dataclasses import asdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable, Sequence

from sentinel.auditstore.store import Store
from sentinel.capture.live import LiveEveDataSource, LiveZeekDataSource
from sentinel.capture.tail import OffsetStore
from sentinel.contracts.datasource import DataSource
from sentinel.correlator import Correlator
from sentinel.correlator.correlator import DEFAULT_CORRELATION_WINDOW_S, _parse_ts
from sentinel.decision import AutonomyController, DecisionEngine, RateLimiter
from sentinel.decision.chain import Facts
from sentinel.logging_setup import get_logger
from sentinel.models import Alert
from sentinel.pilot.runner import _config_view

log = get_logger("sentinel.daemon")


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class LockedEngine:
    """Serialises engine access between the daemon loop and the Ops UI thread.

    DecisionEngine keeps mutable state (rate limiter, pending approvals); the
    embedded UI resolves approvals from a worker thread while the daemon
    evaluates new incidents. Every public call goes through one lock.
    """

    def __init__(self, engine: DecisionEngine) -> None:
        self._engine = engine
        self._lock = threading.RLock()

    def evaluate(self, *a, **kw):
        with self._lock:
            return self._engine.evaluate(*a, **kw)

    def resolve(self, *a, **kw):
        with self._lock:
            return self._engine.resolve(*a, **kw)

    def pending_approvals(self):
        with self._lock:
            return dict(self._engine.pending_approvals())


class Daemon:
    """One poll = ``run_once()``; ``run()`` loops until ``stop`` is set."""

    def __init__(self, *, sources: Sequence[DataSource], engine: DecisionEngine | LockedEngine,
                 store: Store, correlator: Correlator | None = None,
                 clock: Callable[[], datetime] = _utcnow,
                 window_s: int = DEFAULT_CORRELATION_WINDOW_S,
                 health_path: Path | None = None) -> None:
        self._health_path = Path(health_path) if health_path else None
        self._sources = list(sources)
        self._engine = engine
        self._store = store
        self._corr = correlator or Correlator(window_s)
        self._clock = clock
        self._retain = timedelta(seconds=2 * window_s)
        self._buffer: list[Alert] = []
        # story key -> (signals frozenset, alert count) at last decision
        self._decided: dict[tuple[str, str, str], tuple[frozenset, int]] = {}
        self.cycles = 0
        self.decisions = 0

    # -- one cycle ------------------------------------------------------ #

    def run_once(self) -> int:
        """Poll sources, correlate, decide escalated incidents. Returns the
        number of decisions recorded this cycle."""
        for src in self._sources:
            try:
                self._buffer.extend(src.fetch())
            except Exception as exc:     # P4: a bad source never stops the loop
                log.warning("source_fetch_failed",
                            source=getattr(src, "name", "?"), error=str(exc))
        self._prune()
        made = 0
        for inc in self._corr.correlate(self._buffer):
            key = (inc.src_ip, inc.dst_ip, inc.first_ts)
            sigs, n = frozenset(inc.signals), len(inc.alerts)
            prev = self._decided.get(key)
            if prev is not None and not (sigs - prev[0]) and n < 2 * prev[1]:
                continue
            self._decide(inc)
            self._decided[key] = (sigs, n)
            made += 1
        self.cycles += 1
        self.decisions += made
        return made

    def _prune(self) -> None:
        now = self._clock()
        cutoff = now - self._retain
        keep: list[Alert] = []
        for a in self._buffer:
            try:
                if _parse_ts(a.ts) >= cutoff:
                    keep.append(a)
            except ValueError:
                continue                 # unparsable ts cannot be correlated
        self._buffer = keep
        live_firsts = {a.ts for a in keep}
        self._decided = {k: v for k, v in self._decided.items()
                         if k[2] in live_firsts}

    def _decide(self, incident) -> None:
        # Liveness is not yet derived from Zeek conn state; "alive" matches
        # the pilot and keeps the daemon shadow-only (nothing executes).
        decision = self._engine.evaluate(incident, Facts(liveness="alive"))
        rec = decision.recommendation
        self._store.record_decision(
            case_id="live",
            incident_id=decision.incident_id,
            outcome=decision.outcome.value,
            score=float(decision.score),
            base_score=float(decision.base_score),
            tier=decision.tier,
            cap_applied=decision.cap_applied,
            would=decision.would,
            recommendation=(asdict(rec) if rec is not None else {}),
            audit_events=[asdict(e) for e in decision.audit_events],
        )
        log.info("live_decision", incident_id=decision.incident_id,
                 outcome=decision.outcome.value, score=float(decision.score))

    # -- health --------------------------------------------------------- #

    def health(self) -> list[dict]:
        out = []
        for src in self._sources:
            try:
                out.append({"source": getattr(src, "name", "?"), **src.health()})
            except Exception as exc:
                out.append({"source": getattr(src, "name", "?"),
                            "status": "down", "error": str(exc)})
        return out

    def write_health(self) -> None:
        """Atomically publish capture health for read-only consumers (Ops UI)."""
        if self._health_path is None:
            return
        doc = {"mode": "live_shadow", "ts": self._clock().isoformat(),
               "cycles": self.cycles, "decisions": self.decisions,
               "sources": self.health()}
        try:
            tmp = self._health_path.with_suffix(".tmp")
            tmp.write_text(json.dumps(doc, sort_keys=True), encoding="utf-8")
            os.replace(tmp, self._health_path)
        except OSError:
            log.warning("health_write_failed", path=str(self._health_path))

    # -- loop ----------------------------------------------------------- #

    def run(self, stop: threading.Event, poll_interval_s: float = 1.0) -> None:
        log.info("daemon_started", sources=len(self._sources), mode="shadow")
        while not stop.is_set():
            self.run_once()
            self.write_health()
            stop.wait(poll_interval_s)
        log.info("daemon_stopped", cycles=self.cycles, decisions=self.decisions)


def build_daemon(cfg: dict, capture_dir: Path, store: Store, *,
                 state_path: Path | None = None,
                 start_at_end: bool = False) -> Daemon:
    """Wire a shadow daemon from a validated config + a sensor log directory."""
    capture_dir = Path(capture_dir)
    state = OffsetStore(state_path or capture_dir / ".sentinel-offsets.json")
    sources: list[DataSource] = []
    eve = capture_dir / "eve.json"
    sources.append(LiveEveDataSource(eve, state=state, start_at_end=start_at_end))
    for name in ("conn.log", "dns.log", "ssl.log", "notice.log"):
        sources.append(LiveZeekDataSource(capture_dir / name, state=state,
                                          start_at_end=start_at_end))
    limits = cfg["limits"]
    engine = LockedEngine(DecisionEngine(
        config_view=_config_view(cfg),
        clock=_utcnow,
        rate_limiter=RateLimiter(int(limits["max_blocks_per_min"]),
                                 int(limits["max_blocks_per_hour"])),
        controller=AutonomyController(level=int(cfg["autonomy_level"])),
    ))
    return Daemon(sources=sources, engine=engine, store=store,
                  health_path=capture_dir / "live-health.json")
