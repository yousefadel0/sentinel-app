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
    ai = [_ai_row(r) for r in store.query(
        "SELECT ts, status, elapsed_ms, response_verbatim FROM llm_pairs"
        " WHERE case_id IN (?, ?) ORDER BY id DESC LIMIT 3",
        (f"live-{incident_id}", incident_id))]
    return {"incident_id": incident_id, "inputs": inputs, "ai": ai,
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


# -- inbox: what needs a human now ------------------------------------------ #

#: Outcomes that mean "a human should look" (everything else is noise/log).
IMPORTANT_OUTCOMES = ("escalate_human", "human_approval", "auto_act",
                      "auto_throttle", "report_wait", "notify_only")
_OUTCOME_RANK = {o: i for i, o in enumerate(reversed(IMPORTANT_OUTCOMES))}


def inbox(store: Store, *, hours: int = 24,
          now: Optional[datetime] = None) -> dict[str, Any]:
    """Attackers worth attention in the window, grouped by source address,
    plus a one-line summary of everything that was only logged."""
    now = now or datetime.now(timezone.utc)
    since = (now - timedelta(hours=hours)).strftime("%Y-%m-%dT%H:%M:%S")
    rows = store.query(
        "SELECT d.incident_id, d.ts, d.outcome, d.score, c.src_ip, c.dst_ip,"
        " c.attack_type, c.alert_count, c.last_ts,"
        " (SELECT inputs FROM incident_inputs i WHERE i.incident_id = d.incident_id"
        " ORDER BY i.id DESC LIMIT 1), " + _LABEL + _JOIN +
        " WHERE " + _LATEST_DECISION + " AND d.ts >= ? AND d.case_id != 'pilot'",
        (since,))
    groups: dict[str, dict[str, Any]] = {}
    noise_total, noise_types = 0, {}
    for (iid, ts, outcome, score, src, dst, atype, count, last_ts,
         inputs_raw, label) in rows:
        if outcome not in IMPORTANT_OUTCOMES or label in ("false_positive", "benign"):
            noise_total += 1
            key = atype or "Unmapped event"
            noise_types[key] = noise_types.get(key, 0) + 1
            continue
        src = src or "—"
        g = groups.setdefault(src, {
            "src_ip": src, "incidents": 0, "alerts": 0, "targets": set(),
            "types": set(), "max_score": 0.0, "max_conf": None,
            "last_seen": "", "outcome": outcome, "incident_id": iid})
        g["incidents"] += 1
        g["alerts"] += int(count or 0)
        if dst:
            g["targets"].add(dst)
        if atype:
            g["types"].add(atype)
        conf = _json(inputs_raw, {}).get("confidence")
        if conf is not None:
            g["max_conf"] = max(float(conf), g["max_conf"] or 0.0)
        if float(score) >= g["max_score"]:
            g["max_score"] = float(score)
            g["incident_id"] = iid
        if _OUTCOME_RANK.get(outcome, -1) > _OUTCOME_RANK.get(g["outcome"], -1):
            g["outcome"] = outcome
        g["last_seen"] = max(g["last_seen"], str(last_ts or ts))
    attackers = sorted(groups.values(),
                       key=lambda g: (_OUTCOME_RANK.get(g["outcome"], -1),
                                      g["max_score"], g["last_seen"]), reverse=True)
    for g in attackers:
        g["targets"] = sorted(g["targets"])
        g["types"] = sorted(g["types"])
    return {"hours": hours, "attackers": attackers,
            "important_incidents": sum(g["incidents"] for g in attackers),
            "noise_total": noise_total,
            "noise_types": sorted(noise_types.items(), key=lambda kv: -kv[1])[:8]}


# -- AI agent (advisory) ------------------------------------------------------ #

def _ai_row(row) -> dict[str, Any]:
    """One audited LLM call; the opinion is parsed with the SAME strict
    validator the daemon uses, so nothing unvalidated is ever displayed."""
    ts, status, elapsed, response = row
    item = {"ts": ts, "status": status, "elapsed_ms": elapsed, "opinion": None}
    if status == "ok":
        try:
            from sentinel.brain.output import parse_output
            r = parse_output(response)
            item["opinion"] = {"attack_type": r.attack_type, "confidence": r.confidence,
                               "severity": r.severity, "action": r.recommended_action,
                               "rationale": r.rationale}
        except Exception:
            item["status"] = "parse_error"
    return item


def ai_overview(store: Store, *, hours: int = 24,
                now: Optional[datetime] = None) -> dict[str, Any]:
    now = now or datetime.now(timezone.utc)
    since = (now - timedelta(hours=hours)).isoformat()
    by_status = dict(store.query(
        "SELECT status, COUNT(*) FROM llm_pairs WHERE ts >= ? GROUP BY status", (since,)))
    lat = store.query("SELECT AVG(elapsed_ms), MAX(elapsed_ms) FROM llm_pairs"
                      " WHERE ts >= ? AND status = 'ok'", (since,))[0]
    recent = []
    for case_id, ts, status, elapsed, response in store.query(
            "SELECT case_id, ts, status, elapsed_ms, response_verbatim FROM llm_pairs"
            " ORDER BY id DESC LIMIT 20"):
        row = _ai_row((ts, status, elapsed, response))
        row["incident_id"] = case_id[5:] if case_id.startswith("live-") else case_id
        recent.append(row)
    return {"hours": hours, "by_status": by_status,
            "avg_ms": round(lat[0]) if lat[0] is not None else None,
            "max_ms": lat[1], "recent": recent}
