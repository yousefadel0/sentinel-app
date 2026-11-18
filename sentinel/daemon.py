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
from dataclasses import asdict, replace
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
from sentinel.escalation import CriticalWatch
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
                                "notify_only", "report_wait"})


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

    def restore_pending(self, decision):
        with self._lock:
            self._engine.restore_pending(decision)


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
                 executor: Executor | None = None,
                 watch: CriticalWatch | None = None,
                 liveness_check: Callable[[dict], str] | None = None,
                 learning=None, intel=None, cve_intel=None) -> None:
        self._watch = watch
        self._learning = learning
        self._intel = intel
        self._cve_intel = cve_intel
        self._liveness_check = liveness_check
        bind = getattr(liveness_check, "bind_clock", None)
        if bind is not None:
            bind(lambda: self._clock())
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
        self.summary_hour_utc: int | None = None   # daily summary (notifiers)
        self._last_summary_day: str | None = None

    # -- one cycle ------------------------------------------------------ #

    def run_once(self) -> int:
        """Poll sources, correlate, decide escalated incidents. Returns the
        number of decisions recorded this cycle."""
        fresh: list[Alert] = []
        if self._intel is not None:
            self._intel.maybe_refresh()
        for src in self._sources:
            try:
                fresh.extend(src.fetch())
            except Exception as exc:     # P4: a bad source never stops the loop
                log.warning("source_fetch_failed",
                            source=getattr(src, "name", "?"), error=str(exc))
        observe = getattr(self._liveness_check, "observe", None)
        if observe is not None:
            observe(fresh)
        anomalies = self._learning.anomalies(fresh) if self._learning is not None else []
        if self._learning is not None:
            self._learning.observe(fresh)
        # Raw flow/dns records feed the behavioral detectors; only
        # incident-worthy alerts (signature hits, detector output) correlate.
        self._detectors.ingest(fresh)
        self._buffer.extend(a for a in fresh if is_incident_worthy(a))
        self._buffer.extend(self._detectors.detect())
        self._buffer.extend(anomalies)
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
        self._maybe_daily_summary()
        if self._watch is not None:
            self._watch.tick()
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
        ctx = {"incident_id": incident.incident_id,
               "src_ip": incident.src_ip, "dst_ip": incident.dst_ip}
        # Sensor logs alone do not establish a currently live flow.
        try:
            liveness = (self._liveness_check(ctx)
                        if self._liveness_check is not None else "unknown")
        except Exception:
            liveness = "unknown"
        if liveness not in ("alive", "stale", "unknown"):
            liveness = "unknown"
        simulation = bool(self._executor and self._executor.dry_run
                          and liveness == "unknown")
        decision = self._engine.evaluate(
            incident, Facts(liveness=liveness, dry_run_simulation=simulation))
        if self._intel is not None:
            match = self._intel.match(incident.signals)
            if match is not None:
                decision = replace(decision, inputs={
                    **decision.inputs,
                    "mitre_technique_ids": match["technique_ids"],
                    "mitre_catalog_source": match["catalog_source"],
                    "mitre_mapping_confidence": match["confidence"],
                })
        if self._cve_intel is not None:
            cves = self._cve_intel.match(incident.signals)
            if cves:
                decision = replace(decision, inputs={
                    **decision.inputs, "cve_ids": [row["cve_id"] for row in cves],
                    "cve_context": cves})
        self._record(decision, "live")
        self._record_context(incident)
        self._store.record_incident_inputs(incident_id=decision.incident_id,
                                           inputs=dict(decision.inputs))
        ctx["incident_id"] = decision.incident_id
        if self._executor is not None:
            self._executor.handle(decision, ctx, "auto")
        if self._watch is not None:
            self._watch.consider(decision, ctx)
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
        if self._watch is not None:
            self._watch.resolved(decision.incident_id)
        self._enforce_approved(decision, "ops_ui")

    def critical_status(self, incident_id: str):
        return self._watch.status(incident_id) if self._watch else None

    def acknowledge(self, incident_id: str, actor: str = "ops_ui") -> bool:
        """Callback for the Ops UI 'I am handling it' button."""
        return bool(self._watch and self._watch.ack(incident_id, actor))

    def _record_context(self, incident) -> None:
        """Persist who/what/where so the Ops UI can filter and explain."""
        from sentinel.threatintel.attack import map_incident
        mapping = map_incident(incident.signals)
        self._store.record_incident_context(
            incident_id=incident.incident_id,
            src_ip=incident.src_ip, dst_ip=incident.dst_ip,
            attack_type=(mapping.attack_type if mapping else
                         "Baseline anomaly" if "baseline_anomaly" in incident.signals else "Unmapped event"),
            signals=list(incident.signals),
            alert_count=len(incident.alerts),
            first_ts=incident.first_ts, last_ts=incident.last_ts,
            evidence=self._evidence(incident),
            mitre=list(mapping.technique_ids) if mapping else [])

    def _evidence(self, incident) -> list[dict]:
        """What the sensors saw (metadata only) + the attacker's recent
        conversations, so an analyst can answer what/how/where/who."""
        rows: list[dict] = []
        for a in sorted(incident.alerts, key=lambda x: x.ts)[:50]:
            rows.append({
                "kind": "alert", "ts": a.ts, "source": a.source.adapter,
                "ref": a.source.ref, "src": a.src_ip, "sport": a.src_port,
                "dst": a.dst_ip, "dport": a.dst_port, "proto": a.protocol,
                "what": a.meta.label or ", ".join(a.signals),
                "bytes": a.meta.byte_count})
        recent = getattr(self._liveness_check, "recent_flows", None)
        if recent is not None and incident.src_ip:
            for f in recent(incident.src_ip, 30):
                rows.append({**f, "kind": "flow",
                             "ts": datetime.fromtimestamp(f["ts"], timezone.utc).isoformat()})
        return rows

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
                req = self._resolutions.get_nowait()
            except queue.Empty:
                return
            approval_id, approved = req[0], req[1]
            actor = req[2] if len(req) > 2 else "telegram_engineer"
            if approved is None:         # /ack: engineer is handling it
                if self._watch is not None:
                    self._watch.ack(approval_id, actor)
                continue
            try:
                decision = self._engine.resolve(approval_id, approved,
                                                actor=actor)
            except KeyError:
                continue                 # stale/unknown id: nothing to do
            if self._watch is not None:
                self._watch.resolved(approval_id)
            self._record(decision, "telegram")
            self._enforce_approved(decision, "telegram")
            log.info("chat_approval_resolved", approval_id=approval_id,
                     approved=approved, actor=actor)

    def _maybe_daily_summary(self) -> bool:
        """Once a day at ``summary_hour_utc``: what happened in 24 h, by attacker."""
        if self._hub is None or self.summary_hour_utc is None:
            return False
        now = self._clock()
        day = now.strftime("%Y-%m-%d")
        if now.hour < self.summary_hour_utc or self._last_summary_day == day:
            return False
        self._last_summary_day = day
        try:
            from sentinel.ui.analytics import inbox
            data = inbox(self._store, hours=24, now=now)
        except Exception as exc:                  # never break the loop
            log.warning("daily_summary_failed", error=type(exc).__name__)
            return False
        from sentinel.notify.hub import Notification
        pending = len(self._engine.pending_approvals())
        lines = [f"آخر 24 ساعة حتى {now.strftime('%Y-%m-%d %H:%M')} UTC",
                 f"مصادر هجوم: {len(data['attackers'])} · حوادث مهمة: {data['important_incidents']}"
                 f" · ضوضاء مسجّلة فقط: {data['noise_total']}",
                 f"موافقات مفتوحة الآن: {pending}"]
        for g in data["attackers"][:5]:
            lines.append(f"• {g['src_ip']} → {', '.join(g['targets'][:2])}: "
                         f"{', '.join(g['types']) or '—'} (خطورة {g['max_score']:.0%})")
        if not data["attackers"]:
            lines.append("لا هجمات تستحق الانتباه. ✔")
        self._hub.notify_urgent(Notification(
            title="الملخص اليومي", body="\n".join(lines), severity="info",
            incident_id=f"summary-{day}", outcome="summary"))
        return True

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
               "notifications": {"channels": 0 if self._hub is None else len(self._hub._senders),
                                 "delivered": 0 if self._hub is None else self._hub.delivered,
                                 "failed": 0 if self._hub is None else self._hub.failures},
               "sources": self.health()}
        if self._learning is not None:
            doc["learning"] = self._learning.export()
            doc["mode"] = self._learning.mode
        try:
            tmp = self._health_path.with_suffix(".tmp")
            tmp.write_text(json.dumps(doc, sort_keys=True), encoding="utf-8")
            os.replace(tmp, self._health_path)
        except OSError:
            log.warning("health_write_failed", path=str(self._health_path))

    # -- loop ----------------------------------------------------------- #

    def run(self, stop: threading.Event, poll_interval_s: float = 1.0) -> None:
        log.info("daemon_started", sources=len(self._sources),
                 dry_run=True if self._executor is None else self._executor.dry_run)
        if self._approvals is not None:
            self._approvals.start(self._resolutions)
        try:
            while not stop.is_set():
                self.run_once()
                self.write_health()
                self.write_metrics()
                stop.wait(poll_interval_s)
        finally:
            if self._approvals is not None:
                self._approvals.stop()
            if self._hub is not None:
                self._hub.close()
            if self._triage is not None:
                self._triage.close()
            log.info("daemon_stopped", cycles=self.cycles, decisions=self.decisions)


def build_daemon(cfg: dict, capture_dir: Path, store: Store, *,
                 state_path: Path | None = None,
                 start_at_end: bool = False,
                 dry_run: bool = True,
                 liveness_check: Callable[[dict], str] | None = None,
                 learning_path: Path | None = None,
                 intel_path: Path | None = None,
                 cve_path: Path | None = None) -> Daemon:
    """Wire a shadow daemon from a validated config + a sensor log directory."""
    capture_dir = Path(capture_dir)
    from sentinel.learning import LearningProfile
    learning = LearningProfile(learning_path) if learning_path is not None else None
    from sentinel.threatintel.attack import AttackIntel
    intel = AttackIntel(intel_path) if intel_path is not None else None
    from sentinel.threatintel.vulnerabilities import CveIntel
    cve_intel = CveIntel(cve_path) if cve_path is not None else None
    state = OffsetStore(state_path or capture_dir / ".sentinel-offsets.json")
    policy = cfg.get("policy") or {}
    from sentinel.capture.normalizer import configure_noise
    configure_noise(
        suppress_signature_ids=policy.get("suppress_signature_ids", ()),
        suppress_engine_events=policy.get("suppress_engine_events", True))
    if liveness_check is None:
        # Real proof from the sensors' own flow records (never invented).
        from sentinel.capture.liveness import FlowLiveness
        liveness_check = FlowLiveness()
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
    executor = _build_executor(cfg, config_view, store, controller, dry_run,
                               liveness_check=liveness_check,
                               can_act=(lambda: learning.mode == "active")
                               if learning is not None else None)
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
    from sentinel.brain.client import llm_client_from_cfg
    client = llm_client_from_cfg(cfg)
    if client is not None:
        triage = AdvisoryTriage(client)
    cr = cfg.get("critical_response") or {}
    daemon = Daemon(sources=sources, engine=engine, store=store,
                  health_path=capture_dir / "live-health.json",
                  triage=triage, hub=hub, exporter=exporter,
                  approvals=approvals, executor=executor,
                  metrics_path=capture_dir / "sentinel.prom",
                  liveness_check=liveness_check, learning=learning, intel=intel,
                  cve_intel=cve_intel)
    daemon._watch = CriticalWatch(
        store=store, engine=engine, hub=hub, executor=executor,
        clock=_utcnow, record_decision=daemon._record,
        auto_remediate=bool(cr.get("auto_remediate_on_timeout", True)),
        reminder_s=int(cr.get("reminder_minutes", 5)) * 60)
    for item in cfg.get("notifiers") or []:
        if item.get("daily_summary_hour_utc") is not None:
            daemon.summary_hour_utc = int(item["daily_summary_hour_utc"])
            break
    _restore_pending(store, engine, daemon._watch)
    return daemon


def _restore_pending(store: Store, engine: LockedEngine, watch: CriticalWatch) -> None:
    """Rebuild only unresolved, audited approvals with their original deadlines."""
    from sentinel.decision.models import AuditEvent, Decision, Outcome, Recommendation
    from sentinel.timeutil import parse_iso

    rows = store.query(
        "SELECT d.incident_id, d.outcome, d.base_score, d.score, d.tier, "
        "d.cap_applied, d.would, d.recommendation, d.audit_events "
        "FROM decisions d WHERE d.id = "
        "(SELECT MAX(id) FROM decisions WHERE incident_id = d.incident_id) "
        "AND d.outcome IN ('human_approval', 'report_wait')")
    for iid, outcome, base, score, tier, cap, would, raw_rec, raw_events in rows:
        try:
            data = store.query("SELECT inputs FROM incident_inputs WHERE "
                               "incident_id=? ORDER BY id DESC LIMIT 1", (iid,))
            context = store.query("SELECT src_ip, dst_ip FROM incident_context WHERE "
                                  "incident_id=? ORDER BY id DESC LIMIT 1", (iid,))
            if not data or not context:
                raise ValueError("missing incident inputs or context")
            inputs = json.loads(data[0][0])
            deadline = parse_iso(inputs["approval_deadline"])
            rec_data = json.loads(raw_rec)
            rec = Recommendation(**rec_data) if rec_data else None
            events = tuple(AuditEvent(**item) for item in json.loads(raw_events))
            decision = Decision(
                incident_id=iid, outcome=Outcome(outcome), base_score=base,
                score=score, tier=tier, cap_applied=cap,
                audit_events=events, recommendation=rec,
                approval_deadline=deadline, would=would, inputs=inputs)
            engine.restore_pending(decision)
            watch.consider(decision, {"incident_id": iid,
                                     "src_ip": context[0][0], "dst_ip": context[0][1]})
        except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
            log.warning("pending_restore_skipped", incident_id=iid,
                        error=type(exc).__name__)


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
                approvals = TelegramApprovals(
                    item["url_env"], item["chat_id"],
                    allowed_user_ids=item.get("allowed_user_ids"))
    return (NotifierHub(senders) if senders else None), approvals


def _build_executor(cfg: dict, config_view, store, controller,
                    dry_run: bool, *, liveness_check=None, can_act=None) -> Executor:
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
        max_per_hour=int(cfg["limits"]["max_blocks_per_hour"]),
        liveness_check=liveness_check, can_act=can_act)
