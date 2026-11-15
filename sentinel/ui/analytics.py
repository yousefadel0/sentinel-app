"""Read-only analytics for the Ops UI v2 (SELECT-only over the audit store).

Everything here derives from rows the daemon/pilot already wrote:
``decisions`` (what Sentinel decided), ``incident_context`` (who/what/where,
evidence REFERENCES) and ``analyst_notes`` (human verdicts). Nothing is
estimated or invented: when a table has no rows the numbers say so (None /
0), they are never defaulted to something that looks healthy.
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from sentinel.auditstore.store import Store
from sentinel.timeutil import parse_iso

LABELS = ("true_positive", "false_positive", "benign")
PAGE_SIZE = 25

_LATEST_DECISION = ("d.id IN (SELECT MAX(id) FROM decisions"
                    " GROUP BY incident_id)")
_JOIN = (" FROM decisions d LEFT JOIN incident_context c ON c.id ="
         " (SELECT MAX(id) FROM incident_context WHERE incident_id ="
         " d.incident_id)")
ORIGINS = ("live", "replay")
_ORIGIN_SQL = ("CASE WHEN EXISTS (SELECT 1 FROM decisions x WHERE"
               " x.incident_id = d.incident_id AND x.case_id = 'pilot')"
               " THEN 'replay' ELSE 'live' END")
_LABEL = ("(SELECT label FROM analyst_notes n WHERE n.incident_id ="
          " d.incident_id AND n.label != '' ORDER BY n.id DESC LIMIT 1)")


def _json(value: str, default: Any) -> Any:
    try:
        return json.loads(value)
    except (TypeError, ValueError):
        return default


def _ts(value: str) -> Optional[datetime]:
    try:
        return parse_iso(value)
    except ValueError:
        return None


# -- incident list -------------------------------------------------------- #

def incident_list(store: Store, *, outcome: str = "", tier: str = "",
                  attack_type: str = "", ip: str = "", q: str = "",
                  label: str = "", min_score: Optional[float] = None,
                  origin: str = "", page: int = 1) -> dict[str, Any]:
    """Latest decision per incident, joined with context + analyst verdict."""
    where, params = [_LATEST_DECISION], []
    if origin in ORIGINS:
        where.append(_ORIGIN_SQL + " = ?")
        params.append(origin)
    if outcome:
        where.append("d.outcome = ?")
        params.append(outcome)
    if tier:
        where.append("d.tier = ?")
        params.append(tier)
    if attack_type:
        where.append("c.attack_type = ?")
        params.append(attack_type)
    if ip:
        where.append("(c.src_ip = ? OR c.dst_ip = ?)")
        params += [ip, ip]
    if q:
        like = "%" + q.replace("%", "").replace("_", "") + "%"
        where.append("(d.incident_id LIKE ? OR d.would LIKE ?)")
        params += [like, like]
    if min_score is not None:
        where.append("d.score >= ?")
        params.append(float(min_score))
    if label == "unreviewed":
        where.append(_LABEL + " IS NULL")
    elif label in LABELS:
        where.append(_LABEL + " = ?")
        params.append(label)
    clause = " WHERE " + " AND ".join(where)
    total = store.query("SELECT COUNT(*)" + _JOIN + clause, tuple(params))[0][0]
    page = max(1, int(page))
    rows = store.query(
        "SELECT d.incident_id, d.ts, d.outcome, d.score, d.tier, d.would,"
        " d.case_id, c.src_ip, c.dst_ip, c.attack_type, c.alert_count, c.mitre,"
        " (SELECT inputs FROM incident_inputs i WHERE i.incident_id = d.incident_id"
        " ORDER BY i.id DESC LIMIT 1),"
        " " + _LABEL + ", " + _ORIGIN_SQL + _JOIN + clause + " ORDER BY d.id DESC LIMIT ? OFFSET ?",
        tuple(params) + (PAGE_SIZE, (page - 1) * PAGE_SIZE))
    cols = ("incident_id", "ts", "outcome", "score", "tier", "would",
            "case_id", "src_ip", "dst_ip", "attack_type", "alert_count",
            "mitre_raw", "inputs_raw", "label", "origin")
    def project(row):
        item = dict(zip(cols, row))
        item["mitre"] = _json(item.pop("mitre_raw"), [])
        item["confidence"] = _json(item.pop("inputs_raw"), {}).get("confidence")
        return item
    return {"total": int(total), "page": page, "page_size": PAGE_SIZE,
            "pages": max(1, -(-int(total) // PAGE_SIZE)),
            "rows": [project(r) for r in rows]}


def incident_full(store: Store, incident_id: str) -> Optional[dict[str, Any]]:
    dec = store.query(
        "SELECT id, ts, case_id, outcome, score, base_score, tier,"
        " cap_applied, would, recommendation, audit_events FROM decisions"
        " WHERE incident_id = ? ORDER BY id ASC", (incident_id,))
    if not dec:
        return None
    dcols = ("id", "ts", "case_id", "outcome", "score", "base_score", "tier",
             "cap_applied", "would", "recommendation", "audit_events")
    decisions = []
    for r in dec:
        d = dict(zip(dcols, r))
        d["recommendation"] = _json(d["recommendation"], {})
        d["audit_events"] = _json(d["audit_events"], [])
        decisions.append(d)
    ctx_rows = store.query(
        "SELECT ts, src_ip, dst_ip, attack_type, signals, alert_count,"
        " first_ts, last_ts, evidence, mitre FROM incident_context"
        " WHERE incident_id = ? ORDER BY id ASC", (incident_id,))
    ccols = ("ts", "src_ip", "dst_ip", "attack_type", "signals",
             "alert_count", "first_ts", "last_ts", "evidence", "mitre")
    contexts = []
    for r in ctx_rows:
        c = dict(zip(ccols, r))
        for k in ("signals", "evidence", "mitre"):
            c[k] = _json(c[k], [])
        contexts.append(c)
    notes = [dict(zip(("id", "ts", "actor", "label", "note"), r))
             for r in store.query(
                 "SELECT id, ts, actor, label, note FROM analyst_notes"
                 " WHERE incident_id = ? ORDER BY id ASC", (incident_id,))]
    verdict = next((n["label"] for n in reversed(notes) if n["label"]), "")
    inp = store.query(
        "SELECT inputs FROM incident_inputs WHERE incident_id = ?"
        " ORDER BY id DESC LIMIT 1", (incident_id,))
    inputs = _json(inp[0][0], {}) if inp else {}
    is_replay = any(d["case_id"] == "pilot" for d in decisions)
    return {"incident_id": incident_id, "inputs": inputs,
            "origin": "replay" if is_replay else "live", "decisions": decisions,
            "context": contexts[-1] if contexts else None,
            "context_history": len(contexts), "notes": notes,
            "verdict": verdict}


# -- overview ------------------------------------------------------------- #

def origin_counts(store: Store) -> dict[str, int]:
    rows = store.query("SELECT " + _ORIGIN_SQL + ", COUNT(*)" + _JOIN +
                       " WHERE " + _LATEST_DECISION + " GROUP BY 1")
    out = {"live": 0, "replay": 0}
    for name, n in rows:
        out[name] = int(n)
    return out


def decision_latency(store: Store) -> dict[str, Any]:
    """Seconds from the FIRST evidence of an incident to its first decision,
    for LIVE incidents only (replay timestamps are not wall-clock). Both ends
    are real stamps; values outside 0..24h are discarded as clock skew."""
    rows = store.query(
        "SELECT MIN(d.id), MIN(d.ts), c.first_ts FROM decisions d"
        " JOIN incident_context c ON c.incident_id = d.incident_id"
        " WHERE d.case_id = 'live' GROUP BY d.incident_id")
    vals = []
    for _, dts, first in rows:
        a, b = _ts(dts), _ts(first)
        if a and b:
            sec = (a - b).total_seconds()
            if 0 <= sec <= 86400:
                vals.append(sec)
    vals.sort()
    n = len(vals)
    return {"n": n,
            "median_s": round(vals[n // 2], 1) if n else None,
            "p90_s": round(vals[min(n - 1, int(n * 0.9))], 1) if n else None}


def overview(store: Store, buckets: int = 24,
             origin: str = "") -> dict[str, Any]:
    oc = origin_counts(store)
    if origin not in ORIGINS:
        origin = "live" if oc["live"] else ""
    ocl = (" AND " + _ORIGIN_SQL + " = '" + origin + "'") if origin else ""
    latest = store.query(
        "SELECT d.outcome, d.tier, c.src_ip, c.dst_ip, c.attack_type, "
        + _LABEL + _JOIN + " WHERE " + _LATEST_DECISION + ocl)
    outcomes: dict[str, int] = {}
    attack: dict[str, int] = {}
    srcs: dict[str, int] = {}
    dsts: dict[str, int] = {}
    labels = {k: 0 for k in LABELS}
    tiers: dict[str, int] = {}
    for outcome, tier, src, dst, atype, label in latest:
        outcomes[outcome] = outcomes.get(outcome, 0) + 1
        tiers[tier] = tiers.get(tier, 0) + 1
        if atype:
            attack[atype] = attack.get(atype, 0) + 1
        if src:
            srcs[src] = srcs.get(src, 0) + 1
        if dst:
            dsts[dst] = dsts.get(dst, 0) + 1
        if label in labels:
            labels[label] += 1
    total = len(latest)
    reviewed = sum(labels.values())

    stamps = [t for t in (_ts(r[0]) for r in store.query(
        "SELECT d.ts FROM decisions d WHERE 1=1" + ocl.replace(
            _ORIGIN_SQL, _ORIGIN_SQL) + " ORDER BY d.id ASC")) if t]
    timeline: list[dict[str, Any]] = []
    span_days = None
    if stamps:
        end = max(stamps)
        start = min(stamps)
        span_days = round((end - start).total_seconds() / 86400, 2)
        width = max((end - start) / buckets, timedelta(minutes=1))
        counts = [0] * buckets
        for t in stamps:
            idx = min(buckets - 1, int((t - start) / width))
            counts[idx] += 1
        timeline = [{"t": (start + width * i).isoformat(), "n": n}
                    for i, n in enumerate(counts)]

    def top(d: dict[str, int], n: int = 5):
        return sorted(d.items(), key=lambda kv: (-kv[1], kv[0]))[:n]

    fp, tp = labels["false_positive"], labels["true_positive"]
    judged = fp + tp
    return {
        "incidents": total,
        "decision_rows": len(stamps),
        "outcomes": outcomes, "tiers": tiers,
        "attack_types": top(attack, 8),
        "top_sources": top(srcs), "top_targets": top(dsts),
        "labels": labels, "reviewed": reviewed,
        "unreviewed": total - reviewed,
        "analyst_fp_rate": (round(fp / judged, 3) if judged else None),
        "judged": judged,
        "timeline": timeline, "span_days": span_days,
        "with_context": sum(1 for r in latest if r[2]),
        "origin": origin, "origins": oc,
        "latency": decision_latency(store),
    }


def autonomy_readiness(ov: dict[str, Any], level: int,
                       observed_days: int | None = None) -> dict[str, Any]:
    """Advisory view of the §6/§11 evidence gate. NEVER changes the level —
    upgrades stay a manual operator action (Project.md §6)."""
    checks = []
    span = observed_days
    checks.append(("14 يومًا على الأقل من البيانات",
                   span is not None and span >= 14,
                   "لا يوجد ملف تعلّم" if span is None else f"{span} يوم رصد"))
    labeled = ov["judged"]
    checks.append(("عينات مصنّفة بشريًا (20 على الأقل)", labeled >= 20,
                   str(labeled)))
    fp = ov["analyst_fp_rate"]
    checks.append(("معدل الإنذارات الكاذبة أقل من 5%",
                   fp is not None and fp < 0.05,
                   "غير متاح" if fp is None else f"{fp:.1%}"))
    return {"level": level, "checks": checks,
            "eligible": all(ok for _, ok, _ in checks)}
