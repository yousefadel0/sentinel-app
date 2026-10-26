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
import queue
import threading
import time
from collections import deque
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
from sentinel.actuation import Executor
from sentinel.decision import AutonomyController, DecisionEngine, RateLimiter
from sentinel.decision.chain import Facts
from sentinel.detectors import DetectorSuite
from sentinel.detectors.suite import is_incident_worthy
from sentinel.logging_setup import get_logger
from sentinel.models import Alert
from sentinel.pilot.runner import _config_view, asset_hints

log = get_logger("sentinel.daemon")


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class AdvisoryTriage:
    """Non-blocking, rate-capped LLM triage for ambiguous incidents.

    ADVISORY ONLY: results are recorded as verbatim prompt/response pairs
    (G7) and never change a decision. Calls run on one worker thread so the
    hard-cutoff wait never stalls the capture loop; finished pairs are
    drained and written by the loop thread (single SQLite writer).
    """

    def __init__(self, client, *, max_per_min: int = 6,
                 max_pending: int = 4, clock=time.monotonic) -> None:
        from concurrent.futures import ThreadPoolExecutor
        self._client = client
        self._max_per_min = max_per_min
        self._max_pending = max_pending
        self._clock = clock
        self._pool = ThreadPoolExecutor(max_workers=1,
                                        thread_name_prefix="triage")
        self._pending: list = []
        self._sent: deque = deque()
        self.skipped = 0

    def submit(self, case_id: str, alerts, first_seen: str | None) -> bool:
        now = self._clock()
        while self._sent and now - self._sent[0] > 60:
            self._sent.popleft()
        in_flight = sum(1 for f in self._pending if not f.done())
        if len(self._sent) >= self._max_per_min or in_flight >= self._max_pending:
            self.skipped += 1
            return False
        self._sent.append(now)
        self._pending.append(self._pool.submit(
            self._job, case_id, list(alerts), first_seen))
        return True

    def _job(self, case_id, alerts, first_seen):
        from sentinel.brain.audit import InMemoryPairSink
        from sentinel.brain.triage import triage_incident
        sink = InMemoryPairSink()
        triage_incident(case_id, alerts, self._client, sink=sink,
                        first_seen=first_seen)
        return sink.pairs

    def drain(self) -> list:
        pairs, keep = [], []
        for f in self._pending:
            if f.done():
                try:
                    pairs.extend(f.result())
                except Exception:        # P4: never leak into the loop
                    pass
            else:
                keep.append(f)
        self._pending = keep
        return pairs

    def close(self) -> None:
        self._pool.shutdown(wait=False, cancel_futures=True)


#: Outcomes worth a second opinion (the "ambiguous ~10%" of Project.md §5).
AMBIGUOUS_OUTCOMES = frozenset({"human_approval", "escalate_human",
                                "notify_only"})


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
                 health_path: Path | None = None,
                 detectors: DetectorSuite | None = None,
                 triage: AdvisoryTriage | None = None,
                 hub=None, exporter=None, approvals=None,
                 export_every_s: float = 10.0,
                 metrics_path: Path | None = None,
                 executor: Executor | None = None) -> None:
        self._executor = executor
        self._metrics_path = Path(metrics_path) if metrics_path else None
        self._hub, self._exporter = hub, exporter
        self._approvals = approvals
        self._resolutions: queue.Queue = queue.Queue()
        self._export_every = export_every_s
        self._last_export = 0.0
        self._triage = triage
        self._detectors = detectors if detectors is not None else DetectorSuite()
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
        fresh: list[Alert] = []
        for src in self._sources:
            try:
                fresh.extend(src.fetch())
            except Exception as exc:     # P4: a bad source never stops the loop
                log.warning("source_fetch_failed",
                            source=getattr(src, "name", "?"), error=str(exc))
        # Raw flow/dns records feed the behavioral detectors; only
        # incident-worthy alerts (signature hits, detector output) correlate.
        self._detectors.ingest(fresh)
        self._buffer.extend(a for a in fresh if is_incident_worthy(a))
        self._buffer.extend(self._detectors.detect())
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
        self._apply_resolutions()
        if self._executor is not None:
            self._executor.sweep()
        self._export()
        if self._triage is not None:
            from sentinel.pilot.runner import StorePairSink
            sink = StorePairSink(self._store)
            for pair in self._triage.drain():
                sink.append_pair(pair)
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
        self._record(decision, "live")
        self._record_context(incident)
        if self._executor is not None:
            self._executor.handle(decision, {
                "incident_id": decision.incident_id,
                "src_ip": incident.src_ip, "dst_ip": incident.dst_ip}, "auto")
        if self._hub is not None:
            self._hub.notify(decision, incident)
        if (self._triage is not None
                and decision.outcome.value in AMBIGUOUS_OUTCOMES):
            self._triage.submit(f"live-{decision.incident_id}",
                                incident.alerts, incident.first_ts)
        log.info("live_decision", incident_id=decision.incident_id,
                 outcome=decision.outcome.value, score=float(decision.score))

    def _enforce_approved(self, decision, case_id: str) -> None:
        """A human said yes: hand the resolved decision to the executor."""
        if self._executor is None:
            return
        rows = self._store.query(
            "SELECT src_ip, dst_ip FROM incident_context WHERE incident_id = ?"
            " ORDER BY id DESC LIMIT 1", (decision.incident_id,))
        if not rows:
            log.warning("approval_without_context",
                        incident_id=decision.incident_id)
            return
        self._executor.handle(decision, {
            "incident_id": decision.incident_id,
            "src_ip": rows[0][0], "dst_ip": rows[0][1]}, "approved",
            case_id=case_id)

    def execute_approved(self, decision) -> None:
        """Callback for the Ops UI approval route (same seam as chat)."""
        self._enforce_approved(decision, "ops_ui")

    def _record_context(self, incident) -> None:
        """Persist who/what/where so the Ops UI can filter and explain."""
        from sentinel.threatintel.attack import map_incident
        mapping = map_incident(incident.signals)
        self._store.record_incident_context(
            incident_id=incident.incident_id,
            src_ip=incident.src_ip, dst_ip=incident.dst_ip,
            attack_type=(mapping.attack_type if mapping else ""),
            signals=list(incident.signals),
            alert_count=len(incident.alerts),
            first_ts=incident.first_ts, last_ts=incident.last_ts,
            evidence=[a.source.ref for a in incident.alerts[:50]],
            mitre=list(mapping.technique_ids) if mapping else [])

    def _record(self, decision, case_id: str) -> None:
        rec = decision.recommendation
        self._store.record_decision(
            case_id=case_id,
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

    def _apply_resolutions(self) -> None:
        """Chat approvals, applied on THIS thread through Engine.resolve —
        the same seam, validator chain, window and audit trail as the UI."""
        while True:
            try:
                approval_id, approved = self._resolutions.get_nowait()
            except queue.Empty:
                return
            try:
                decision = self._engine.resolve(approval_id, approved)
            except KeyError:
                continue                 # stale/unknown id: nothing to do
            self._record(decision, "telegram")
            self._enforce_approved(decision, "telegram")
            log.info("chat_approval_resolved", approval_id=approval_id,
                     approved=approved)

    def _export(self) -> None:
        if self._exporter is None:
            return
        now = time.monotonic()
        if now - self._last_export >= self._export_every:
            self._last_export = now
            self._exporter.run_once()

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

    def metrics_text(self) -> str:
        """Prometheus exposition text (for the node_exporter textfile
        collector — no listening port, no auth surface)."""
        lines = []

        def gauge(name, value, help_, kind="gauge", labels=""):
            if value is None:
                return
            if not any(l.startswith(f"# TYPE {name} ") for l in lines):
                lines.append(f"# HELP {name} {help_}")
                lines.append(f"# TYPE {name} {kind}")
            lines.append(f"{name}{labels} {value}")

        gauge("sentinel_cycles_total", self.cycles, "Daemon poll cycles", "counter")
        gauge("sentinel_decisions_total", self.decisions,
              "Decisions recorded", "counter")
        gauge("sentinel_alert_buffer_size", len(self._buffer),
              "Correlation buffer size")
        rank = {"healthy": 0, "degraded": 1, "down": 2}
        for h in self.health():
            lab = '{source="%s"}' % str(h.get("source", "?")).replace('"', "")
            gauge("sentinel_source_status", rank.get(h.get("status"), 2),
                  "0=healthy 1=degraded 2=down", labels=lab)
            gauge("sentinel_source_packet_drops", h.get("packet_drops"),
                  "Sensor-reported kernel drops", labels=lab)
            gauge("sentinel_source_malformed_total",
                  h.get("malformed_lines_skipped"),
                  "Malformed input lines skipped", "counter", labels=lab)
        if self._executor is not None:
            gauge("sentinel_enforcement_dry_run",
                  1 if self._executor.dry_run else 0,
                  "1 = shadow/dry-run, 0 = enforcing")
            gauge("sentinel_actions_executed_total", self._executor.executed,
                  "Enforcement actions executed", "counter")
            gauge("sentinel_actions_active", len(self._executor.active()),
                  "Enforcement actions currently in force")
        if self._hub is not None:
            gauge("sentinel_notifications_delivered_total", self._hub.delivered,
                  "Notifications delivered", "counter")
            gauge("sentinel_notifications_failed_total", self._hub.failures,
                  "Notification send failures", "counter")
            gauge("sentinel_notifications_suppressed_total", self._hub.suppressed,
                  "Notifications dropped by the rate cap", "counter")
        if self._exporter is not None:
            gauge("sentinel_siem_exported_total", self._exporter.exported,
                  "Verdicts exported to the SIEM", "counter")
        if self._triage is not None:
            gauge("sentinel_llm_triage_skipped_total", self._triage.skipped,
                  "LLM triage calls skipped by the rate cap", "counter")
        return "\n".join(lines) + "\n"

    def write_metrics(self) -> None:
        if self._metrics_path is None:
            return
        try:
            tmp = self._metrics_path.with_suffix(".tmp")
            tmp.write_text(self.metrics_text(), encoding="utf-8")
            os.replace(tmp, self._metrics_path)
        except OSError:
            log.warning("metrics_write_failed", path=str(self._metrics_path))

    def write_health(self) -> None:
        """Atomically publish capture health for read-only consumers (Ops UI)."""
        if self._health_path is None:
            return
        ex = self._executor
        doc = {"mode": ("live_enforcing" if ex and not ex.dry_run
                        else "live_shadow"),
               "ts": self._clock().isoformat(),
               "cycles": self.cycles, "decisions": self.decisions,
               "enforcement": {"dry_run": True if ex is None else ex.dry_run,
                               "executed": 0 if ex is None else ex.executed,
                               "active": [] if ex is None else ex.active()},
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
        if self._approvals is not None:
            self._approvals.start(self._resolutions)
        while not stop.is_set():
            self.run_once()
            self.write_health()
            self.write_metrics()
            stop.wait(poll_interval_s)
        if self._approvals is not None:
            self._approvals.stop()
        if self._hub is not None:
            self._hub.close()
        log.info("daemon_stopped", cycles=self.cycles, decisions=self.decisions)


def build_daemon(cfg: dict, capture_dir: Path, store: Store, *,
                 state_path: Path | None = None,
                 start_at_end: bool = False,
                 dry_run: bool = True) -> Daemon:
    """Wire a shadow daemon from a validated config + a sensor log directory."""
    capture_dir = Path(capture_dir)
    state = OffsetStore(state_path or capture_dir / ".sentinel-offsets.json")
    sources: list[DataSource] = []
    hints = asset_hints(cfg)
    eve = capture_dir / "eve.json"
    sources.append(LiveEveDataSource(eve, state=state, start_at_end=start_at_end,
                                     critical_assets=hints))
    for name in ("conn.log", "dns.log", "ssl.log", "notice.log"):
        sources.append(LiveZeekDataSource(capture_dir / name, state=state,
                                          start_at_end=start_at_end,
                                          critical_assets=hints))
    limits = cfg["limits"]
    controller = AutonomyController(level=int(cfg["autonomy_level"]))
    config_view = _config_view(cfg)
    engine = LockedEngine(DecisionEngine(
        config_view=config_view,
        clock=_utcnow,
        rate_limiter=RateLimiter(int(limits["max_blocks_per_min"]),
                                 int(limits["max_blocks_per_hour"])),
        controller=controller,
    ))
    executor = _build_executor(cfg, config_view, store, controller, dry_run)
    hub, approvals = _build_notifiers(cfg)
    siem = cfg.get("siem") or {}
    exporter = None
    if siem.get("enabled"):
        inbound = siem.get("inbound") or {}
        if inbound.get("enabled") and inbound.get("alerts_file"):
            from sentinel.siem.inbound import WazuhAlertsFileDataSource
            sources.append(WazuhAlertsFileDataSource(
                inbound["alerts_file"], state=state,
                start_at_end=start_at_end))
        outbound = siem.get("outbound") or {}
        if outbound.get("enabled"):
            from sentinel.siem.outbound import SiemExporter
            exporter = SiemExporter(
                store, outbound["endpoint"],
                capture_dir / ".sentinel-siem-export.json",
                token_env=outbound.get("token_env"),
                batch_size=int(outbound["batch_size"]))
    triage = None
    brain = cfg.get("brain") or {}
    env_var = brain.get("llm_endpoint_env")
    if env_var and os.environ.get(env_var):
        from sentinel.brain.client import LLMClient
        triage = AdvisoryTriage(LLMClient(
            env_var, timeout_s=int(brain["timeout_s"]),
            hard_cutoff_s=int(brain["hard_cutoff_s"])))
    return Daemon(sources=sources, engine=engine, store=store,
                  health_path=capture_dir / "live-health.json",
                  triage=triage, hub=hub, exporter=exporter,
                  approvals=approvals, executor=executor,
                  metrics_path=capture_dir / "sentinel.prom")


def _build_notifiers(cfg: dict):
    """(NotifierHub | None, TelegramApprovals | None) from the notifiers block."""
    from sentinel.notify import NotifierHub, TelegramSender, WebhookSender
    from sentinel.notify.approvals import TelegramApprovals

    senders, approvals = [], None
    for item in cfg.get("notifiers") or []:
        if item["type"] == "webhook":
            senders.append(WebhookSender(item["url_env"],
                                         item.get("format", "generic")))
        else:
            senders.append(TelegramSender(item["url_env"], item["chat_id"]))
            if item.get("approvals") and approvals is None:
                approvals = TelegramApprovals(item["url_env"], item["chat_id"])
    return (NotifierHub(senders) if senders else None), approvals


def _build_executor(cfg: dict, config_view, store, controller,
                    dry_run: bool) -> Executor:
    """Executor over the actuators named in config. In dry-run (the default)
    actuators are still constructed so intents and health are accurate, but
    the executor never calls them."""
    from sentinel.actuators import NftablesLocalActuator, WebhookSoarActuator
    from sentinel.validator import Validator

    validator = Validator(config_view)
    actuators = {}
    for item in cfg.get("actuators") or []:
        if item["type"] == "nftables_local":
            actuators["nftables_local"] = NftablesLocalActuator(validator)
        elif item["type"] == "webhook_soar":
            actuators["webhook_soar"] = WebhookSoarActuator(
                validator, item["url"])
    return Executor(
        store=store, validator=validator, actuators=actuators,
        autonomy_level=lambda: controller.level, dry_run=dry_run,
        max_per_hour=int(cfg["limits"]["max_blocks_per_hour"]))
