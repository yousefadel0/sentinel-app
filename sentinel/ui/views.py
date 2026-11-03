"""Read-only projections for the Minimal Ops UI (M7).

Pure observer by construction: every function here reads existing SQLite
tables via ``sentinel.auditstore.Store`` / reuses
``sentinel.pilot.kpi.compute_kpis`` verbatim, or probes replay capture
files through the REAL ``CaptureHealthTracker`` semantics. No new data
stores; no writes anywhere except the approval flow in app.py, which
persists through the SAME record_decision call shape as the CLI path.

KPI names (P5/Q1 legacy pin) are preserved EXACTLY as produced by
compute_kpis: separate ``mttd_seconds`` and ``mttd_replay_seconds`` keys;
no blended aggregate key is ever emitted.
"""
from __future__ import annotations

import csv
import io
import json
import time
from html import escape
from pathlib import Path
from typing import Any

from sentinel.auditstore.store import Store
from sentinel.capture.health import CaptureHealthTracker
from sentinel.pilot.kpi import compute_kpis

#: How many recent incidents/decisions the viewer surfaces.
RECENT_LIMIT = 20


def kpis(store: Store) -> dict[str, Any]:
    """KPI counters read from the store — names preserved exactly (P5)."""
    return compute_kpis(store)


def recent_incidents(store: Store, limit: int = RECENT_LIMIT) -> list[dict[str, Any]]:
    """Most recent decisions rows, newest first (read-only projection)."""
    rows = store.query(
        "SELECT id, ts, case_id, incident_id, outcome, score, base_score,"
        " tier, cap_applied, would FROM decisions"
        " ORDER BY id DESC LIMIT ?", (limit,))
    cols = ("id", "ts", "case_id", "incident_id", "outcome", "score",
            "base_score", "tier", "cap_applied", "would")
    return [dict(zip(cols, r)) for r in rows]


def pending_queue(engine: Any) -> list[dict[str, Any]]:
    """Pending human approvals from the REAL engine seam.

    ``engine`` is the injected DecisionEngine (embedded deployment) or
    None (standalone observer) ⇒ honest empty queue with a note rather
    than invented data.
    """
    if engine is None:
        return []
    out = []
    for approval_id, dec in sorted(engine.pending_approvals().items()):
        out.append({
            "approval_id": approval_id,
            "outcome": dec.outcome.value,
            "tier": dec.tier,
            "score": float(dec.score),
            "deadline": dec.approval_deadline.isoformat()
            if dec.approval_deadline else None,
            "would": dec.would,
            "critical": bool((getattr(dec, "inputs", None) or {}).get("critical")),
        })
    return out


LIVE_HEALTH_MAX_AGE_S = 30.0


def _live_health(capture_dir: Path | None) -> list[dict[str, Any]] | None:
    """Sources published by the live daemon (live-health.json), or None.

    A stale file means the daemon itself stopped: every source is then
    reported ``down`` rather than trusting its last words.
    """
    if capture_dir is None:
        return None
    path = Path(capture_dir) / "live-health.json"
    try:
        doc = json.loads(path.read_text(encoding="utf-8"))
        age = time.time() - path.stat().st_mtime
    except (OSError, ValueError):
        return None
    out = []
    for src in doc.get("sources", []):
        item = dict(src)
        if age > LIVE_HEALTH_MAX_AGE_S:
            item["status"] = "down"
            item["daemon_stale"] = True
        out.append(item)
    return out


def capture_health(capture_dir: Path | None) -> list[dict[str, Any]]:
    """Per-file replay capture health — REAL tracker semantics, zero writes.

    Probes the *.eve.jsonl / conn.log files the pilot runner actually
    ingests. Uses CaptureHealthTracker.snapshot() so the shape is exactly
    HealthSnapshot.to_dict(); missing dir/files report status=down
    honestly (never invented numbers).
    """
    live = _live_health(capture_dir)
    if live is not None:
        return live
    if capture_dir is None or not Path(capture_dir).is_dir():
        return [{"file": str(capture_dir), "status": "down",
                 "heartbeat_ts": None, "packet_drops": None,
                 "coverage_percent": None, "last_alert_ts": None,
                 "source_type": "file_replay",
                 "malformed_lines_skipped": 0}]
    out = []
    import datetime as _dt
    for path in sorted(
        [*Path(capture_dir).glob("*.eve.jsonl"), *Path(capture_dir).glob("conn.log")]
    ):
        tracker = CaptureHealthTracker(interface=path.name)
        # record_heartbeat seeds the tracker from the file's REAL mtime so
        # snapshot() freshness semantics (healthy/degraded/down) apply to
        # actual capture provenance, not UI wall-clock assumptions.
        hb_iso = _dt.datetime.fromtimestamp(
            path.stat().st_mtime, tz=_dt.timezone.utc).isoformat()
        tracker.record_heartbeat(ts=hb_iso)
        snap = tracker.snapshot(source_type="file_replay")
        snap.packet_drops = 0          # documented zero — file replay
        snapshot = snap.to_dict()
        snapshot["file"] = path.name
        out.append(snapshot)
    return out


def decision_row_bytes(store: Store, incident_id: str) -> dict[str, Any] | None:
    """Latest decisions row for an incident as a plain dict (parity aid)."""
    rows = store.query(
        "SELECT id, ts, case_id, incident_id, outcome, score, base_score,"
        " tier, cap_applied, would, recommendation, audit_events"
        " FROM decisions WHERE incident_id=? ORDER BY id DESC LIMIT 1",
        (incident_id,))
    if not rows:
        return None
    cols = ("id", "ts", "case_id", "incident_id", "outcome", "score",
            "base_score", "tier", "cap_applied", "would",
            "recommendation", "audit_events")
    return dict(zip(cols, rows[0]))


def serialize(obj: Any) -> str:
    """Stable JSON for htmx payloads (sorted keys, no surprises)."""
    return json.dumps(obj, sort_keys=True, default=str)


# Human-facing HTML projections. The JSON endpoints above remain unchanged.
def _e(value: Any) -> str:
    return escape(str(value if value is not None else "—"), quote=True)


def _empty(message: str) -> str:
    return f'<p class="empty-state">{_e(message)}</p>'


def _source_note(snap: dict[str, Any]) -> str:
    if snap.get("source_type") == "live_file":
        drops = snap.get("packet_drops")
        drops_txt = "غير متاح" if drops is None else str(drops)
        stale = " · الـ daemon متوقف" if snap.get("daemon_stale") else ""
        return f"تتبّع مباشر لسجلات المستشعر (shadow) · فقد الحزم: {drops_txt}{stale}"
    return "مصدر تجريبي من ملف · وليس التقاطًا مباشرًا من الشبكة"


def render_capture(capture_dir: Path | None) -> str:
    if capture_dir is None:
        return _empty("لم يتم ربط مجلد capture بالواجهة.")
    snapshots = capture_health(capture_dir)
    if not snapshots or (len(snapshots) == 1 and snapshots[0].get("file") == str(capture_dir)):
        return _empty("لم أجد ملفات أحداث داخل مجلد capture.")
    labels = {"healthy": "الملف متاح", "degraded": "الملف قديم", "down": "غير متاح"}
    cards = []
    for snap in snapshots:
        state = str(snap.get("status", "down"))
        cards.append(
            '<article class="source-card">'
            f'<span class="status status-{_e(state)}">{_e(labels.get(state, state))}</span>'
            f'<strong>{_e(snap.get("file"))}</strong>'
            f'<span>{_e(_source_note(snap))}</span>'
            f'<span>آخر تعديل: {_e(snap.get("heartbeat_ts"))}</span>'
            '</article>')
    return "".join(cards)


def render_approvals(engine: Any) -> str:
    if engine is None:
        return _empty("وضع مشاهدة فقط: محرك الموافقات غير مربوط في هذا التشغيل.")
    queue = pending_queue(engine)
    if not queue:
        return _empty("لا توجد قرارات تنتظر موافقة بشرية الآن.")
    rows = []
    for item in queue:
        aid = _e(item.get("approval_id"))
        rows.append(
            '<tr>'
            f'<td><code title="{aid}">{aid[:18]}…</code></td>'
            f'<td>{_e(item.get("outcome"))}</td>'
            f'<td>{float(item.get("score", 0)):.0%}</td>'
            f'<td>{_e(item.get("deadline"))}</td>'
            '<td class="actions">'
            f'<button class="button button-approve" hx-post="/approvals/{aid}/approve" '
            'hx-target="#approval-action-result" hx-swap="innerHTML" '
            'hx-confirm="هل تريد اعتماد هذا القرار؟">اعتماد</button> '
            f'<button class="button button-deny" hx-post="/approvals/{aid}/deny" '
            'hx-target="#approval-action-result" hx-swap="innerHTML" '
            'hx-confirm="هل تريد رفض هذا القرار؟">رفض</button>'
            '</td></tr>')
    return ('<div class="table-wrap"><table><thead><tr><th>رقم الحادثة</th>'
            '<th>نوع القرار</th><th>الدرجة</th><th>الموعد النهائي</th>'
            '<th>الإجراء</th></tr></thead><tbody>' + "".join(rows) +
            '</tbody></table></div><div id="approval-action-result" aria-live="polite"></div>')


def render_incidents(store: Store | None) -> str:
    if store is None:
        return _empty("لا يوجد سجل تدقيق مربوط بالواجهة.")
    incidents = recent_incidents(store)
    if not incidents:
        return _empty("لا توجد حوادث مسجلة بعد. شغّل الـPilot لتجربة البيانات.")
    outcomes = {
        "log_only": "تسجيل فقط", "notify_only": "إشعار فقط",
        "human_approval": "بانتظار موافقة", "escalate_human": "تصعيد بشري",
        "auto_act": "إجراء آلي", "auto_throttle": "تقييد آلي",
    }
    rows = []
    for item in incidents:
        iid = _e(item.get("incident_id"))
        outcome = str(item.get("outcome", ""))
        score = max(0.0, min(1.0, float(item.get("score", 0))))
        rows.append(
            '<tr>'
            f'<td>{_e(item.get("ts"))}</td>'
            f'<td><a href="#" hx-get="/dashboard/incident/{iid}" '
            f'hx-target="#incident-detail" hx-swap="innerHTML">'
            f'<code title="{iid}">{iid[:18]}…</code></a></td>'
            f'<td><span class="outcome outcome-{_e(outcome)}">'
            f'{_e(outcomes.get(outcome, outcome))}</span></td>'
            f'<td><span class="score"><span style="width:{score * 100:.1f}%"></span></span> '
            f'<b>{score:.0%}</b></td>'
            f'<td>{_e(item.get("tier"))}</td>'
            f'<td class="reason">{_e(item.get("would"))}</td>'
            '</tr>')
    return ('<div class="table-wrap"><table><thead><tr><th>الوقت</th>'
            '<th>الحادثة</th><th>النتيجة</th><th>الدرجة</th><th>الفئة</th>'
            '<th>التفسير</th></tr></thead><tbody>' + "".join(rows) +
            '</tbody></table></div>')


def render_kpis(store: Store | None) -> str:
    if store is None:
        return _empty("لا يوجد سجل تدقيق لقراءة المؤشرات.")
    data = kpis(store)
    replay = data["mttd_replay_seconds"]
    generator = data["mttd_seconds"]
    fp = data["fp_rate"]
    latency = data["llm_latency_ms"]

    def metric(title: str, value: Any, detail: str, tone: str = "") -> str:
        return (f'<article class="metric {tone}"><span>{_e(title)}</span>'
                f'<strong>{_e(value)}</strong><small>{_e(detail)}</small></article>')

    replay_value = f'{replay["avg"]} ث' if replay["avg"] is not None else "—"
    gen_value = f'{generator["avg"]} ث' if generator["avg"] is not None else "—"
    fp_value = (f'{fp["flagged"]} / {fp["benign_injections"]}'
                if fp["benign_injections"] else "لا توجد عينات سليمة")
    latency_value = f'{latency["p50"]} ms' if latency["p50"] is not None else "—"
    outcomes = data["decisions_by_outcome"]
    outcome_text = "، ".join(f'{name}: {count}' for name, count in sorted(outcomes.items())) or "لا توجد قرارات"
    metrics = (
        metric("الحوادث المسجلة", data["incidents"], "قرارات محفوظة في سجل التدقيق"),
        metric("زمن الكشف في replay", replay_value, f'متوسط تجريبي · عدد العينات {replay["n"]}'),
        metric("زمن الكشف في التوليد", gen_value, f'متوسط تجريبي · عدد العينات {generator["n"]}'),
        metric("إنذارات على أحداث سليمة", fp_value, "المعلّمة / إجمالي العينات"),
        metric("إجراءات نُفذت", data["actions_executed"], "تأثير فعلي على النظام", "metric-safe"),
        metric("إجراءات مسجلة", data["actions_recorded"], "نوايا محفوظة في السجل"),
        metric("عمليات التراجع", data["rollbacks"], "إجمالي المسجل"),
        metric("زمن استجابة الذكاء الاصطناعي", latency_value, f'الوسيط · عدد العينات {latency["n"]}'),
    )
    return ('<div class="metrics-grid">' + "".join(metrics) +
            '</div><p class="subtle"><strong>توزيع القرارات:</strong> ' +
            _e(outcome_text) + '</p>')


def render_report_link(report_dir: str | Path) -> str:
    """Show the latest generated report, if the pilot has produced one."""
    latest = Path(report_dir) / "latest.html"
    if not latest.is_file():
        return _empty("لا يوجد تقرير بعد. شغّل Pilot لإنتاج تقرير للهجمات والقرارات.")
    return ('<p>التقرير المفصل لآخر تشغيل جاهز.</p>'
            '<a class="button button-approve" href="/reports/latest" target="_blank" '
            'rel="noopener">فتح تقرير آخر تشغيل</a>')


# -- Phase 2: incident detail, audit search, export (read-only) -------------- #

_DECISION_COLS = ("id", "ts", "case_id", "incident_id", "outcome", "score",
                  "base_score", "tier", "cap_applied", "would",
                  "recommendation", "audit_events")


def _decode(row: tuple) -> dict[str, Any]:
    d = dict(zip(_DECISION_COLS, row))
    for key in ("recommendation", "audit_events"):
        try:
            d[key] = json.loads(d[key])
        except (TypeError, ValueError):
            pass
    return d


def incident_detail(store: Store, incident_id: str) -> dict[str, Any] | None:
    """Full decision history of one incident (oldest first) + LLM pairs."""
    rows = store.query(
        "SELECT " + ", ".join(_DECISION_COLS) +
        " FROM decisions WHERE incident_id=? ORDER BY id ASC", (incident_id,))
    if not rows:
        return None
    pairs = store.query(
        "SELECT ts, case_id, status, elapsed_ms, digest FROM llm_pairs"
        " WHERE case_id IN (?, ?) ORDER BY id ASC",
        (incident_id, f"pilot-{incident_id}"))
    return {
        "incident_id": incident_id,
        "decisions": [_decode(r) for r in rows],
        "llm_pairs": [dict(zip(("ts", "case_id", "status", "elapsed_ms",
                                "digest"), p)) for p in pairs],
    }


def audit_search(store: Store, *, outcome: str | None = None,
                 case_id: str | None = None, tier: str | None = None,
                 q: str | None = None, min_score: float | None = None,
                 limit: int = 100, offset: int = 0) -> list[dict[str, Any]]:
    """Filtered decisions listing — parametrised SELECT only."""
    limit = max(1, min(int(limit), 1000))
    offset = max(0, int(offset))
    where, params = [], []
    for col, val in (("outcome", outcome), ("case_id", case_id), ("tier", tier)):
        if val:
            where.append(f"{col} = ?")
            params.append(val)
    if q:
        where.append("(incident_id LIKE ? OR would LIKE ?)")
        like = "%" + q.replace("%", "").replace("_", "") + "%"
        params += [like, like]
    if min_score is not None:
        where.append("score >= ?")
        params.append(float(min_score))
    sql = ("SELECT " + ", ".join(_DECISION_COLS[:10]) + " FROM decisions" +
           (" WHERE " + " AND ".join(where) if where else "") +
           " ORDER BY id DESC LIMIT ? OFFSET ?")
    rows = store.query(sql, tuple(params) + (limit, offset))
    return [dict(zip(_DECISION_COLS[:10], r)) for r in rows]


def _csv_safe(value: Any) -> Any:
    """Neutralise spreadsheet formula injection in exported text cells."""
    if isinstance(value, str) and value[:1] in ("=", "+", "-", "@", "\t", "\r"):
        return "'" + value
    return value


def audit_csv(rows: list[dict[str, Any]]) -> str:
    buf = io.StringIO()
    w = csv.writer(buf)
    cols = _DECISION_COLS[:10]
    w.writerow(cols)
    for r in rows:
        w.writerow([_csv_safe(r.get(c)) for c in cols])
    return buf.getvalue()


def render_incident_detail(store: Store | None, incident_id: str) -> str:
    if store is None:
        return _empty("لا يوجد سجل تدقيق مربوط بالواجهة.")
    detail = incident_detail(store, incident_id)
    if detail is None:
        return _empty("لا توجد حادثة بهذا المعرّف.")
    blocks = []
    for d in detail["decisions"]:
        events = d["audit_events"] if isinstance(d["audit_events"], list) else []
        ev_html = "".join(
            f'<li><code>{_e(e.get("name"))}</code> — {_e(e.get("detail"))}</li>'
            for e in events if isinstance(e, dict)) or "<li>لا أحداث تدقيق</li>"
        rec = d["recommendation"] if isinstance(d["recommendation"], dict) else {}
        rec_html = _e(", ".join(f"{k}={v}" for k, v in sorted(rec.items()))) or "—"
        blocks.append(
            '<article class="source-card">'
            f'<span class="status">{_e(d["outcome"])}</span>'
            f'<strong>{_e(d["ts"])} · {_e(d["case_id"])}</strong>'
            f'<span>الدرجة {float(d["score"]):.0%} (الأساس {float(d["base_score"]):.0%})'
            f' · الفئة {_e(d["tier"])} · السقف: {_e(d["cap_applied"])}</span>'
            f'<span>{_e(d["would"])}</span>'
            f'<span>التوصية: {rec_html}</span>'
            f'<ul>{ev_html}</ul></article>')
    pairs = detail["llm_pairs"]
    note = (f'<p class="subtle">عدد تفاعلات LLM المسجلة: {len(pairs)}</p>'
            if pairs else "")
    return (f'<h3><code>{_e(incident_id)}</code></h3>'
            '<div class="source-grid">' + "".join(blocks) + "</div>" + note)


def settings_view(cfg: dict) -> dict[str, Any]:
    """Redacted effective config for the read-only settings page.

    Secrets never live in the config (only the NAMES of environment
    variables), and even those are reduced to "is it set" here.
    """
    import os
    env_names = []
    brain = cfg.get("brain") or {}
    if brain.get("llm_endpoint_env"):
        env_names.append(brain["llm_endpoint_env"])
    if (cfg.get("ops_ui") or {}).get("auth_token_env"):
        env_names.append(cfg["ops_ui"]["auth_token_env"])
    notifiers = cfg.get("notifiers") or []
    for n in notifiers:
        env_names.append(n.get("url_env", ""))
    siem = cfg.get("siem") or {}
    for part in ("inbound", "outbound"):
        tok = (siem.get(part) or {}).get("token_env")
        if tok and (siem.get(part) or {}).get("enabled"):
            env_names.append(tok)
    siem_txt = "معطّل"
    if siem.get("enabled"):
        parts = [p for p in ("inbound", "outbound")
                 if (siem.get(p) or {}).get("enabled")]
        siem_txt = "مفعّل: " + ", ".join(parts) if parts else "مفعّل بلا اتجاهات"
    limits = cfg.get("limits") or {}
    return {
        "autonomy_level": int(cfg.get("autonomy_level", 0) or 0),
        "limits": {"max_blocks_per_min": limits.get("max_blocks_per_min", "—"),
                   "max_blocks_per_hour": limits.get("max_blocks_per_hour", "—"),
                   "default_ttl_min": limits.get("default_ttl_min", "—")},
        "site": (cfg.get("site") or {}).get("name", "—"),
        "critical_assets": [
            {"ip": a.get("ip", ""), "hostname": a.get("hostname", "")}
            for a in (cfg.get("site") or {}).get("critical_assets", [])],
        "monitored_vlans": [str(x) for x in cfg.get("monitored_vlans", [])],
        "asymmetric_risk": (cfg.get("placement") or {}).get("asymmetric_risk", "—"),
        "env": [(n, bool(os.environ.get(n))) for n in env_names if n],
        "notifiers": [n.get("type", "?") for n in notifiers],
        "siem": siem_txt,
    }
