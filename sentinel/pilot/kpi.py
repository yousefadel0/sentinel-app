"""KPI pipeline (M6) — REAL numbers from the append-only audit store.

D4 semantics, pinned verbatim:
* MTTD (generator path)   = incident_created_at − ground-truth injection ts,
  where incident_created_at is the harness's stream-driven virtual clock at
  evaluation time (= last member alert ts of the incident).
* mttd_replay (replay path) = same arithmetic against the STREAM-DRIVEN
  VIRTUAL CLOCK for CICIDS2017/pcap replay slices, attributed via the slice
  manifest's first_attack_flow identity.
* fp_rate                 = benign-injected incidents flagged ÷ total benign
  injections, reported as n/m (never a bare float).
* actions / rollbacks     = row counts in the audit store's actions /
  rollbacks tables.

Q1 pin: generator-path and replay-path MTTDs are TWO SEPARATE names
(`mttd_seconds`, `mttd_replay_seconds`) and are NEVER blended into one
summary line or one average.
"""
from __future__ import annotations

import json
from datetime import datetime
from typing import Any

from sentinel.auditstore.store import Store

#: Decision outcomes that count as "flagged" for FP-rate purposes.
#: LOG_ONLY / NOTIFY_ONLY are watchful-but-silent; anything stronger means
#: the pilot raised its voice on a purely-benign incident.
_FLAGGED_OUTCOMES = frozenset({
    "auto_act", "auto_throttle", "human_approval", "escalate_human",
})


def _parse_iso(ts: str) -> datetime | None:
    try:
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        return dt if dt.tzinfo else None
    except ValueError:
        return None


def compute_kpis(store: Store) -> dict[str, Any]:
    """Aggregate KPIs from store rows. Honest zeros when empty."""
    decisions = store.rows("decisions")
    kpi_events = store.rows("kpis_events")

    mttd_gen: list[float] = []
    mttd_replay: list[float] = []
    fp_flagged = 0
    fp_benign_total = 0

    for row in kpi_events:
        name, value, detail = row["name"], float(row["value"]), row["detail"]
        meta = json.loads(detail) if detail.strip() else {}
        path_kind = meta.get("path")          # "generator" | "replay"
        benign = bool(meta.get("benign"))

        if name == "mttd":
            if path_kind == "replay":
                mttd_replay.append(value)
            elif path_kind == "generator":
                mttd_gen.append(value)
        elif name == "fp_event" and benign:
            fp_benign_total += 1
            if meta.get("flagged"):
                fp_flagged += 1

    def _avg(values: list[float]) -> float | None:
        return round(sum(values) / len(values), 3) if values else None

    outcomes: dict[str, int] = {}
    for row in decisions:
        outcomes[row["outcome"]] = outcomes.get(row["outcome"], 0) + 1

    llm_pairs = store.count("llm_pairs")
    elapsed_rows = store.query(
        "SELECT elapsed_ms FROM llm_pairs WHERE status='ok'")
    latencies = [int(r[0]) for r in elapsed_rows]

    return {
        "incidents": len(decisions),
        "decisions_by_outcome": outcomes,
        "mttd_seconds": {"n": len(mttd_gen), "avg": _avg(mttd_gen)},
        "mttd_replay_seconds": {"n": len(mttd_replay),
                                "avg": _avg(mttd_replay)},
        "fp_rate": {"flagged": fp_flagged, "benign_injections": fp_benign_total},
        "actions_recorded": store.count("actions"),
        "actions_executed": int(store.query(
            "SELECT COUNT(*) FROM actions WHERE executed=1")[0][0]),
        "rollbacks": store.count("rollbacks"),
        "llm_pairs": llm_pairs,
        "llm_latency_ms": {"n": len(latencies),
                           "p50": _avg([float(x) for x in latencies])},
    }
