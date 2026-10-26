"""Pilot runner (M6) — drives Sentinel over generated captures.

Two paths, both offline, ONE pipeline (D4):
* generator path — synthetic eve.jsonl fixtures from tools/attackers;
* replay path    — committed CICIDS-style slices via the slice manifest
  (tools/make_fixtures.py output), same adapters, virtual clock.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import time
from collections import defaultdict
from dataclasses import asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sentinel.auditstore.store import Store
from sentinel.capture.adapters_file import EveFileDataSource, ZeekLogFileDataSource
from sentinel.capture.eve_parser import iter_eve
from sentinel.config.loader import ConfigError, load_config
from sentinel.correlator import Correlator
from sentinel.decision import AutonomyController, ConfigView, DecisionEngine, RateLimiter
from sentinel.decision.chain import Facts
from sentinel.logging_setup import get_logger
from sentinel.pilot.kpi import _FLAGGED_OUTCOMES, compute_kpis
from sentinel.threatintel.attack import enrich_mapping, load_attack_catalog, map_incident
from sentinel.threatintel.report import new_report, write_report
from sentinel.threatintel.vulnerabilities import extract_cve_ids, lookup_nvd_cve

log = get_logger("sentinel.pilot.runner")


class VirtualClock:
    """Injected clock that only ever advances to ingested event times."""

    def __init__(self) -> None:
        self._now = datetime(1970, 1, 1, tzinfo=timezone.utc)

    def advance_to(self, ts_iso: str) -> None:
        dt = _parse_ts(ts_iso)
        if dt is not None and dt > self._now:
            self._now = dt

    def __call__(self) -> datetime:
        return self._now


def _parse_ts(ts: str) -> datetime | None:
    try:
        dt = datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except ValueError:
        return None


class StorePairSink:
    """Adapts brain.audit.PairSink onto Store.record_llm_pair (G7)."""

    def __init__(self, store: Store) -> None:
        self._store = store

    def append_pair(self, pair) -> None:
        self._store.record_llm_pair(
            case_id=pair.case_id,
            prompt_verbatim=pair.prompt_verbatim,
            response_verbatim=pair.response_verbatim,
            status=pair.status,
            elapsed_ms=int(pair.elapsed_ms),
            digest=pair.digest(),
        )


def _load_manifest(path):
    """Slice manifest from make_fixtures.py (replay path)."""
    data = json.loads(path.read_text(encoding="utf-8"))
    for key in ("slice_id", "source", "flows"):
        if key not in data:
            raise ValueError(f"manifest {path}: missing '{key}'")
    return data


def _truth_map(capture_dir):
    """ref ("file.jsonl#i") -> sentinel_truth meta, read with the SAME
    committed parser the adapter uses so line indices align exactly."""
    truth = {}
    for eve_file in sorted(capture_dir.glob("*.eve.jsonl")):
        try:
            stream = list(iter_eve(eve_file))
        except OSError:
            continue
        for i, raw in enumerate(stream, start=1):
            meta = raw.get("sentinel_truth")
            if isinstance(meta, dict):
                truth[f"{eve_file.name}#{i}"] = {
                    "kind": str(meta.get("kind", "")),
                    "family": str(meta.get("family", "")),
                }
    return truth


def _event_context(capture_dir):
    """Keep bounded report evidence only; never copy raw event payloads."""
    context = defaultdict(lambda: {"cve_ids": set(), "signatures": set()})
    for eve_file in sorted(capture_dir.glob("*.eve.jsonl")):
        try:
            stream = iter_eve(eve_file)
            for i, raw in enumerate(stream, start=1):
                alert = raw.get("alert") if isinstance(raw.get("alert"), dict) else {}
                ref = f"{eve_file.name}#{i}"
                entry = context[ref]
                entry["cve_ids"].update(extract_cve_ids(raw))
                signature = alert.get("signature")
                if signature:
                    entry["signatures"].add(str(signature)[:300])
        except OSError:
            continue
    return context


_SIGNAL_FAMILY = {
    "scan": "scan",
    "auth_fail_burst": "brute_force",
    "volume_spike": "ddos_volumetric",
    "beacon_periodic": "c2_beacon",
    "dns_tunneling": "dns_tunneling",
}


def _replay_flow_for(incident, manifest):
    """Manifest flow identity match for replay attribution.

    Identity rule (documented): a flow matches an incident when the flow's
    dst_ip equals the incident's dst_ip AND its family appears among the
    families implied by the incident's member signals. flow_id rides the
    KPI audit detail.
    """
    if not manifest:
        return None
    inc_fams = {_SIGNAL_FAMILY[s]
                for a in incident.alerts for s in a.signals
                if s in _SIGNAL_FAMILY}
    for flow in manifest.get("flows", []):
        if str(flow.get("dst_ip", "")) == incident.dst_ip                 and str(flow.get("family", "")) in inc_fams:
            return flow
    return None


def _config_view(cfg):
    """Project validated config onto the engine's read-only view.

    Documented mapping choice (Q3): configured critical assets carry
    criticality="high"; every other endpoint defaults to low.
    """
    crit_ips = frozenset(str(a["ip"]) for a in cfg["site"]["critical_assets"])
    limits = cfg["limits"]
    return ConfigView(
        critical_assets=crit_ips,
        monitored_vlans=frozenset(str(v) for v in cfg["monitored_vlans"]),
        asymmetric_risk=str(cfg["placement"]["asymmetric_risk"]),
        max_blocks_per_min=int(limits["max_blocks_per_min"]),
        max_blocks_per_hour=int(limits["max_blocks_per_hour"]),
        autonomy_level=int(cfg["autonomy_level"]),
    )


def run_pilot(config_path, capture_dir, manifest_path=None, *,
              report_dir=None, attack_catalog_path="data/attack/enterprise-attack.json",
              enrich_vulnerabilities=False):
    """Execute one offline pass; optionally write JSON/HTML incident reports."""
    cfg = load_config(config_path)
    store_cfg = cfg.get("audit_store") or {}
    if not isinstance(store_cfg, dict) or not store_cfg.get("path"):
        # §8/D5 declares audit_store OPTIONAL for the appliance at large, but
        # the pilot persists every decision + verbatim pair — fail closed with
        # a clear refusal rather than silently dropping the audit trail.
        raise ConfigError(
            "pilot requires `audit_store.path` (append-only SQLite audit "
            "store, D5): add the block to the config or point it at an "
            "existing store (ref §8)"
        )
    store = Store(store_cfg["path"])
    try:
        manifest = _load_manifest(manifest_path) if manifest_path else None
        truth = _truth_map(capture_dir)
        event_context = _event_context(capture_dir)
        attack_catalog = load_attack_catalog(attack_catalog_path)
        report_incidents = []
        enrichment_errors = []
        nvd_cache = {}

        # -- ingest (same M1 file adapters as production replay) -------- #
        alerts = []
        for eve_file in sorted(capture_dir.glob("*.eve.jsonl")):
            alerts.extend(EveFileDataSource(
                eve_file, signal_key="sentinel_signal").fetch())
        for zeek_log in sorted(capture_dir.glob("conn.log")):
            alerts.extend(ZeekLogFileDataSource(zeek_log).fetch())

        clock = VirtualClock()
        engine = DecisionEngine(
            config_view=_config_view(cfg),
            clock=clock,
            rate_limiter=RateLimiter(int(cfg["limits"]["max_blocks_per_min"]),
                                     int(cfg["limits"]["max_blocks_per_hour"])),
            controller=AutonomyController(level=int(cfg["autonomy_level"])),
        )
        correlator = Correlator()
        decisions_eff = []  # (effective ts, outcome)

        for incident in correlator.correlate(alerts):
            clock.advance_to(incident.last_ts)      # D4 evaluation time
            decision = engine.evaluate(incident, Facts(liveness="alive"))
            rec = decision.recommendation
            store.record_decision(
                case_id="pilot",
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
            family_mapping = map_incident(incident.signals)
            mitre_context = enrich_mapping(family_mapping, attack_catalog)
            cve_ids = sorted({cve for alert in incident.alerts
                              for cve in event_context[alert.source.ref]["cve_ids"]})
            signatures = sorted({sig for alert in incident.alerts
                                 for sig in event_context[alert.source.ref]["signatures"]})
            vulnerability_context = []
            for cve_id in cve_ids:
                nvd_item = {"cve_id": cve_id,
                            "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
                            "source": "CVE identifier in event evidence; NVD lookup disabled"}
                if enrich_vulnerabilities:
                    if cve_id not in nvd_cache:
                        if nvd_cache:
                            time.sleep(6)  # respect unauthenticated NVD rate limits
                        try:
                            nvd_cache[cve_id] = lookup_nvd_cve(cve_id)
                        except Exception as exc:
                            nvd_cache[cve_id] = {**nvd_item, "found": None,
                                                 "lookup_error": str(exc)[:300]}
                            enrichment_errors.append(f"{cve_id}: {str(exc)[:300]}")
                    nvd_item = nvd_cache[cve_id]
                vulnerability_context.append(nvd_item)
            rec_data = asdict(rec) if rec is not None else None
            action = (rec_data or {}).get("action")
            if action:
                action_summary = f"أوصى المحرك بـ {action}; لم ينفذ Pilot أي إجراء."
            else:
                action_summary = "لم يقترح المحرك إجراءً؛ القرار محفوظ للمراجعة."
            report_incidents.append({
                "incident_id": incident.incident_id,
                "attack_type": family_mapping.attack_type if family_mapping else "غير مصنف",
                "signals": list(incident.signals),
                "first_seen": incident.first_ts, "last_seen": incident.last_ts,
                "src_ip": incident.src_ip, "dst_ip": incident.dst_ip,
                "alert_count": len(incident.alerts),
                "evidence_refs": [a.source.ref for a in incident.alerts],
                "signatures": signatures,
                "cve_ids": cve_ids,
                "mitre_attack": mitre_context,
                "vulnerabilities": vulnerability_context,
                "decision": {
                    "outcome": decision.outcome.value,
                    "score": round(float(decision.score), 4),
                    "base_score": round(float(decision.base_score), 4),
                    "tier": decision.tier,
                    "reason": decision.would,
                    "recommendation": rec_data,
                    "action_summary": action_summary,
                    "executed": False,
                },
            })
            decisions_eff.append((clock(), decision.outcome.value))

            # -- MTTD attribution (Q1: two names, never blended) ------- #
            flow = _replay_flow_for(incident, manifest)
            if flow is not None:
                truth_dt = _parse_ts(str(flow.get("first_attack_ts", "")))
                path_kind = "replay"
                family = str(flow.get("family", ""))
                flow_id = str(flow.get("flow_id", ""))
            else:
                attack_members = [
                    a for a in incident.alerts
                    if truth.get(a.source.ref, {}).get("kind") == "attack"]
                if not attack_members:
                    continue        # no ground-truth attack member -> skip
                truth_dt = min(dt for dt in (_parse_ts(a.ts)
                                             for a in attack_members) if dt)
                fams = sorted({truth[a.source.ref]["family"]
                               for a in attack_members})
                path_kind, family, flow_id = "generator", fams[0], ""
            if truth_dt is None:
                log.warning("mttd_truth_ts_unparsable",
                            incident_id=decision.incident_id)
                continue
            value = max((clock() - truth_dt).total_seconds(), 0.0)
            store.record_kpi_event(
                case_id="pilot", name="mttd", value=value,
                detail=json.dumps({"path": path_kind, "family": family,
                                   "flow_id": flow_id}, sort_keys=True))

        # -- benign FP accounting (D4 attribution via effective ts) ----- #
        for eve_file in sorted(capture_dir.glob("*.eve.jsonl")):
            try:
                stream = list(iter_eve(eve_file))
            except OSError:
                continue
            for i, raw in enumerate(stream, start=1):
                meta = raw.get("sentinel_truth") or {}
                if meta.get("kind") != "benign":
                    continue
                benign_dt = _parse_ts(str(raw.get("timestamp", "")))
                flagged = any(
                    outcome in _FLAGGED_OUTCOMES and eff_dt >= benign_dt
                    for eff_dt, outcome in decisions_eff)                     if benign_dt is not None else False
                store.record_kpi_event(
                    case_id="pilot", name="fp_event", value=1,
                    detail=json.dumps({"benign": True, "flagged": flagged},
                                      sort_keys=True))

        # -- bounded LLM triage (G7): only when endpoint env is set ----- #
        env_var = str(cfg["brain"]["llm_endpoint_env"])
        if os.environ.get(env_var):
            try:
                from sentinel.brain.client import LLMClient
                from sentinel.brain.triage import triage_incident

                client = LLMClient(
                    env_var,
                    timeout_s=int(cfg["brain"]["timeout_s"]),
                    hard_cutoff_s=int(cfg["brain"]["hard_cutoff_s"]))
                sink = StorePairSink(store)
                for incident in correlator.correlate(alerts):
                    result, _safe = triage_incident(
                        f"pilot-{incident.incident_id}",
                        list(incident.alerts), client, sink=sink)
                    if result is not None:
                        log.info("triage_recorded",
                                 incident_id=incident.incident_id)
            except Exception as exc:   # P4: offline sandbox must not crash
                log.warning("triage_skipped", error=str(exc))

        kpis = compute_kpis(store)
        if report_dir is not None:
            run_id = datetime.now(timezone.utc).strftime("sentinel-%Y%m%dT%H%M%SZ-") + os.urandom(3).hex()
            report = new_report(
                run_id=run_id,
                mode="ملفات replay / shadow فقط",
                capture_files=[p.name for p in sorted(capture_dir.iterdir()) if p.is_file()],
                incidents=report_incidents,
                kpis=kpis,
                attack_catalog_source=(
                    attack_catalog.get("source") if attack_catalog else
                    "MITRE ATT&CK curated mappings; full STIX catalog not synced"),
                nvd_enabled=bool(enrich_vulnerabilities),
            )
            report["enrichment_errors"] = enrichment_errors
            report_paths = write_report(report, report_dir)
            kpis["report"] = report_paths
        return kpis
    finally:
        store.close()


def main(argv=None):
    ap = argparse.ArgumentParser(prog="pilot-run")
    ap.add_argument("--config", required=True, type=Path)
    ap.add_argument("--capture-dir", required=True, type=Path)
    ap.add_argument("--manifest", type=Path, default=None,
                    help="slice manifest for replay-path MTTD")
    ap.add_argument("--report-dir", type=Path, default=Path("reports"),
                    help="directory for per-run JSON and HTML incident reports")
    ap.add_argument("--attack-catalog", type=Path,
                    default=Path("data/attack/enterprise-attack.json"),
                    help="optional local MITRE ATT&CK STIX cache")
    ap.add_argument("--enrich-vulnerabilities", action="store_true",
                    help="perform read-only NVD lookups for CVE IDs found in capture evidence")
    ap.add_argument("--no-dry-run", dest="no_dry_run", action="store_true",
                    help="accepted for CLI parity; the pilot is SHADOW-ALWAYS "
                         "and executes nothing regardless (G2/P5)")
    args = ap.parse_args(argv)

    try:
        kpis = run_pilot(
            args.config, args.capture_dir, args.manifest,
            report_dir=args.report_dir,
            attack_catalog_path=args.attack_catalog,
            enrich_vulnerabilities=args.enrich_vulnerabilities,
        )
    except ConfigError as exc:
        print(f"pilot-run: config refused: {exc}", file=sys.stderr)
        return 2
    print(json.dumps(kpis, indent=2, sort_keys=True))
    if kpis.get("report"):
        print(f"HTML report: {kpis['report']['html']}")
        print(f"JSON report: {kpis['report']['json']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
