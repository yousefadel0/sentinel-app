"""Ops UI v2 — HTML for every page (Arabic RTL, htmx fragments).

Pure rendering: functions take already-fetched data and return escaped HTML.
No function here touches the store, the engine or the network, so the
security properties live in one place (app.py guards + analytics SELECTs).
Styling is inline because the only unauthenticated asset allowed is the
vendored htmx file (DP2).
"""
from __future__ import annotations

from html import escape
from typing import Any, Optional
from urllib.parse import urlencode

OUTCOME_AR = {
    "log_only": "تسجيل فقط", "notify_only": "إشعار فقط",
    "human_approval": "بانتظار موافقة", "escalate_human": "تصعيد بشري",
    "auto_act": "إجراء آلي", "auto_throttle": "تقييد آلي",
}
ATTACK_AR = {
    "Network service discovery": "مسح الشبكة",
    "Brute force": "تخمين كلمات المرور",
    "Network denial of service": "حجب خدمة (DDoS)",
    "Application layer protocol (possible C2)": "اتصال قيادة وتحكم (C2)",
    "Application layer protocol: DNS": "تسريب عبر DNS",
}
LABEL_AR = {"true_positive": "هجوم حقيقي", "false_positive": "إنذار كاذب",
            "benign": "نشاط سليم", "": "لم تُراجع"}
STATUS_AR = {"healthy": "سليم", "degraded": "متأخر", "down": "متوقف"}


def e(value: Any) -> str:
    return escape(str(value if value is not None else "—"), quote=True)


def empty(message: str) -> str:
    return '<p class="empty">%s</p>' % e(message)


def pill(kind: str, text: str) -> str:
    return '<span class="pill pill-%s">%s</span>' % (e(kind), e(text))


def outcome_pill(outcome: str) -> str:
    return pill(outcome, OUTCOME_AR.get(outcome, outcome))


def label_pill(label: Optional[str]) -> str:
    key = label or ""
    return pill("lbl-" + (key or "none"), LABEL_AR.get(key, key))


def origin_pill(origin: Optional[str]) -> str:
    if origin == "replay":
        return pill("degraded", "replay · بيانات مسجلة")
    return pill("healthy", "حي")


def score_bar(score: float) -> str:
    s = max(0.0, min(1.0, float(score)))
    return ('<span class="bar"><i style="width:%.0f%%"></i></span> <b>%.0f%%</b>'
            % (s * 100, s * 100))


def short(value: str, n: int = 18) -> str:
    v = str(value or "")
    return v if len(v) <= n else v[:n] + "…"


# -- shell ----------------------------------------------------------------- #

NAV = (("overview", "نظرة عامة"), ("incidents", "الحوادث"),
       ("approvals", "الموافقات"), ("sources", "المصادر"),
       ("audit", "التدقيق"), ("settings", "الإعدادات"))

CSS = """
:root{color-scheme:dark;--bg:#0b1220;--p:#111c2e;--p2:#16243a;--line:#24344d;--tx:#e7eef9;--mu:#9aabc3;--bl:#61a9ff;--gr:#42d392;--am:#f4bd50;--rd:#ff7b8a}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--tx);font:15px/1.65 "Segoe UI",Tahoma,sans-serif}
a{color:var(--bl);text-decoration:none}code{font-family:Consolas,monospace;direction:ltr;unicode-bidi:embed;font-size:12.5px}
.top{position:sticky;top:0;z-index:5;background:#0d1626ee;border-bottom:1px solid var(--line);backdrop-filter:blur(6px)}
.top-in{max-width:1500px;margin:auto;padding:10px 22px;display:flex;gap:18px;align-items:center;flex-wrap:wrap}
.brand{font-weight:800;font-size:19px}.brand small{display:block;font-size:11px;color:var(--mu);font-weight:400}
nav{display:flex;gap:4px;flex-wrap:wrap}nav button{background:none;border:0;color:var(--mu);padding:8px 14px;border-radius:9px;font:inherit;cursor:pointer}
nav button.on,nav button:hover{background:var(--p2);color:var(--tx)}
.mode{margin-inline-start:auto}
.wrap{max-width:1500px;margin:auto;padding:20px 22px 60px;display:grid;grid-template-columns:1fr;gap:18px}
.wrap.has-drawer{grid-template-columns:minmax(0,1fr) 440px}
@media(max-width:1100px){.wrap.has-drawer{grid-template-columns:1fr}}
.card{background:var(--p);border:1px solid var(--line);border-radius:14px;padding:16px 18px;margin-bottom:16px}
.card h2{margin:0 0 4px;font-size:17px}.card .sub{color:var(--mu);font-size:13px;margin:0 0 12px}
.grid{display:grid;gap:12px;grid-template-columns:repeat(auto-fit,minmax(200px,1fr))}
.kpi{background:var(--p2);border:1px solid var(--line);border-radius:12px;padding:12px 14px}
.kpi span{display:block;color:var(--mu);font-size:12.5px}.kpi b{font-size:26px;display:block;line-height:1.2}.kpi small{color:var(--mu);font-size:12px}
.kpi.ok b{color:var(--gr)}.kpi.warn b{color:var(--am)}.kpi.bad b{color:var(--rd)}
table{width:100%;border-collapse:collapse;font-size:13.5px}th,td{padding:8px 9px;border-bottom:1px solid var(--line);text-align:start;vertical-align:top}
th{color:var(--mu);font-weight:600;font-size:12px;white-space:nowrap}tr:hover td{background:#14223a}
.tw{overflow-x:auto}.pill{display:inline-block;border-radius:999px;padding:2px 10px;font-size:12px;font-weight:700;background:#25334a;color:#d5e1f3;white-space:nowrap}
.pill-auto_act,.pill-auto_throttle,.pill-lbl-true_positive{background:#40232c;color:#ffb5c0}
.pill-human_approval,.pill-escalate_human{background:#493717;color:#ffe0a0}
.pill-healthy,.pill-lbl-benign{background:#123a2c;color:#a8f0cc}.pill-degraded{background:#493717;color:#ffe0a0}.pill-down{background:#40232c;color:#ffb5c0}
.pill-lbl-false_positive{background:#1c3250;color:#a9d0ff}.pill-lbl-none{background:#1b2638;color:var(--mu)}
.bar{display:inline-block;width:70px;height:7px;background:#223149;border-radius:9px;vertical-align:middle;overflow:hidden}.bar i{display:block;height:100%;background:var(--bl)}
.empty{color:var(--mu);padding:18px;border:1px dashed var(--line);border-radius:10px;text-align:center}
form.filters{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:8px;margin-bottom:12px}
input,select,textarea{background:#0e1929;border:1px solid var(--line);color:var(--tx);border-radius:8px;padding:7px 9px;font:inherit;width:100%}
.btn{background:var(--p2);border:1px solid var(--line);color:var(--tx);border-radius:9px;padding:7px 14px;cursor:pointer;font:inherit}
.btn:hover{border-color:var(--bl)}.btn-go{background:#12395f;border-color:#2c6aa8}.btn-ok{background:#123a2c;border-color:#2a7a5a}.btn-no{background:#40232c;border-color:#8a3a4a}
.pager{display:flex;gap:10px;align-items:center;margin-top:10px;color:var(--mu)}
.drawer{position:sticky;top:70px;align-self:start;max-height:calc(100vh - 90px);overflow:auto}
.tl{border-inline-start:2px solid var(--line);margin:8px 0;padding-inline-start:14px}.tl>div{margin-bottom:12px}
.chips{display:flex;gap:6px;flex-wrap:wrap}.chip{background:#1b2a42;border-radius:7px;padding:1px 8px;font-size:12px}
.cols{display:grid;gap:16px;grid-template-columns:repeat(auto-fit,minmax(320px,1fr))}
.hbar{display:flex;align-items:center;gap:8px;margin:5px 0;font-size:13px}.hbar .nm{width:150px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.hbar .tr{flex:1;height:9px;background:#223149;border-radius:9px;overflow:hidden}.hbar .tr i{display:block;height:100%;background:var(--bl)}
.note{color:var(--mu);font-size:12.5px}.warnbox{background:#2b2412;border:1px solid #5b4a1b;border-radius:10px;padding:10px 12px;color:#ffe0a0;font-size:13px}
"""

SHELL = """<!doctype html><html lang="ar" dir="rtl"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Sentinel | لوحة التحكم</title>
<script src="/static/htmx.min.js"></script><style>%(css)s</style></head><body>
<header class="top"><div class="top-in"><div class="brand">Sentinel<small>مركز مراقبة القرارات الأمنية</small></div>
<nav id="nav">%(nav)s</nav><div class="mode" id="mode" hx-get="/ui/mode" hx-trigger="load, every 20s"></div></div></header>
<div class="wrap" id="wrap"><main id="view" hx-get="/ui/overview" hx-trigger="load"></main>
<aside id="drawer" class="drawer" style="display:none"></aside></div>
<script>
function openDrawer(){document.getElementById('drawer').style.display='block';document.getElementById('wrap').classList.add('has-drawer')}
function closeDrawer(){var d=document.getElementById('drawer');d.style.display='none';d.innerHTML='';document.getElementById('wrap').classList.remove('has-drawer')}
document.getElementById('nav').addEventListener('click',function(ev){var b=ev.target.closest('button');if(!b)return;
document.querySelectorAll('#nav button').forEach(function(x){x.classList.remove('on')});b.classList.add('on');closeDrawer()});
document.body.addEventListener('htmx:afterSwap',function(ev){if(ev.target.id==='drawer'){openDrawer()}});
document.querySelector('#nav button').classList.add('on');
</script></body></html>"""


def shell() -> str:
    nav = "".join(
        '<button hx-get="/ui/%s" hx-target="#view" hx-swap="innerHTML">%s</button>'
        % (k, e(v)) for k, v in NAV)
    return SHELL % {"css": CSS, "nav": nav}


def mode_badge(mode: dict) -> str:
    if mode.get("live"):
        txt = "حي · shadow" if mode.get("daemon_fresh") else "حي · الـ daemon متوقف"
        return pill("healthy" if mode.get("daemon_fresh") else "down", txt)
    return pill("degraded", "عرض بيانات مسجلة (replay)")


# -- overview -------------------------------------------------------------- #

def _hbars(pairs, total: int, label_map=None) -> str:
    if not pairs:
        return empty("لا توجد بيانات")
    top = max(n for _, n in pairs) or 1
    out = []
    for name, n in pairs:
        nm = (label_map or {}).get(name, name)
        out.append('<div class="hbar"><span class="nm" title="%s">%s</span>'
                   '<span class="tr"><i style="width:%.0f%%"></i></span><b>%d</b></div>'
                   % (e(nm), e(nm), 100.0 * n / top, n))
    return "".join(out)


def _timeline(points) -> str:
    if not points:
        return empty("لا توجد قرارات بعد")
    top = max(p["n"] for p in points) or 1
    w, h, n = 640, 110, len(points)
    bw = w / n
    bars = "".join(
        '<rect x="%.1f" y="%.1f" width="%.1f" height="%.1f" rx="2" fill="#61a9ff"><title>%s: %d</title></rect>'
        % (i * bw + 1, h - 8 - (h - 16) * p["n"] / top, max(bw - 2, 1),
           (h - 16) * p["n"] / top, e(p["t"][:16]), p["n"])
        for i, p in enumerate(points))
    return ('<svg viewBox="0 0 %d %d" preserveAspectRatio="none" width="100%%" height="%d" role="img" '
            'aria-label="القرارات عبر الزمن">%s</svg>'
            '<p class="note">من <code>%s</code> إلى <code>%s</code></p>'
            % (w, h, h, bars, e(points[0]["t"][:16]), e(points[-1]["t"][:16])))


def overview(ov: dict, readiness: dict, kp: dict, pending: int) -> str:
    def kpi(title, value, sub="", tone=""):
        return ('<div class="kpi %s"><span>%s</span><b>%s</b><small>%s</small></div>'
                % (tone, e(title), e(value), e(sub)))

    fp = ov["analyst_fp_rate"]
    lat = ov["latency"]
    lat_val = "—" if lat["median_s"] is None else "%s ث" % lat["median_s"]
    lat_sub = ("الوسيط من أول دليل إلى القرار · %d حادثة حية · p90 %s ث"
               % (lat["n"], lat["p90_s"])) if lat["n"] else \
        "لا توجد حوادث حية بعد؛ لا يُحسب رقم بدل الأرقام الحقيقية"
    kpis = "".join((
        kpi("زمن الاستجابة الفعلي", lat_val, lat_sub),
        kpi("الحوادث", ov["incidents"], "حادثة فريدة في السجل"),
        kpi("بانتظار موافقتك", pending, "قرارات تحتاج بشرًا",
            "warn" if pending else "ok"),
        kpi("لم تُراجع بعد", ov["unreviewed"], "بدون تصنيف محلل",
            "warn" if ov["unreviewed"] else "ok"),
        kpi("إنذارات كاذبة (محلل)",
            "—" if fp is None else "%.0f%%" % (fp * 100),
            "من %d حادثة حُكم عليها" % ov["judged"]),
        kpi("إجراءات نُفذت", kp.get("actions_executed", 0),
            "تأثير فعلي على الشبكة", "ok"),
        kpi("مدة البيانات", "—" if ov["span_days"] is None
            else "%s يوم" % ov["span_days"], "من أول قرار لآخره"),
    ))
    outcomes = sorted(ov["outcomes"].items(), key=lambda kv: -kv[1])
    checks = "".join(
        '<tr><td>%s</td><td>%s</td><td>%s</td></tr>'
        % (e(name), pill("healthy" if ok else "degraded", "تحقق" if ok else "لم يتحقق"), e(val))
        for name, ok, val in readiness["checks"])
    gate = pill("healthy" if readiness["eligible"] else "degraded",
                "مؤهل للنظر في الرفع" if readiness["eligible"] else "غير مؤهل بعد")
    ctx_note = ""
    if ov["incidents"] and ov["with_context"] < ov["incidents"]:
        ctx_note = ('<p class="note">%d حادثة بلا سياق (قبل تشغيل الـ daemon الحي): '
                    'المصدر والهدف لا يظهران لها.</p>'
                    % (ov["incidents"] - ov["with_context"]))
    oc = ov["origins"]
    sw = "".join(
        '<button class="btn%s" hx-get="/ui/overview?origin=%s" hx-target="#view">%s (%d)</button> '
        % (" btn-go" if ov["origin"] == key else "", key, label, n)
        for key, label, n in (("", "الكل", oc["live"] + oc["replay"]),
                              ("live", "حي", oc["live"]),
                              ("replay", "replay", oc["replay"])))
    if ov["origin"] == "replay" or (not ov["origin"] and oc["replay"]):
        banner = ('<div class="warnbox" style="margin-bottom:12px">هذه الأرقام تشمل حوادث <b>replay</b>: '
                  'ملفات مسجلة أو بيانات اصطناعية من الـ pilot، وليست ترافيك شبكتك الحي. '
                  'اختر "حي" لترى ما رصده الحساس فعلًا.</div>')
    elif not oc["live"] and not oc["replay"]:
        banner = '<div class="warnbox" style="margin-bottom:12px">لا توجد أي حوادث مسجلة بعد.</div>'
    else:
        banner = ""
    origin_bar = '<div style="margin-bottom:12px">%s</div>%s' % (sw, banner)
    return (
        origin_bar +
        '<div class="grid" hx-get="/ui/overview?origin=%s" hx-trigger="every 20s" hx-target="#view">%s</div>' % (ov["origin"], kpis) +
        '<div class="card" style="margin-top:16px"><h2>القرارات عبر الزمن</h2>'
        '<p class="sub">عدد القرارات المسجلة في كل فترة</p>%s</div>' % _timeline(ov["timeline"]) +
        '<div class="cols"><div class="card"><h2>توزيع النتائج</h2>%s</div>'
        '<div class="card"><h2>أنواع الهجمات</h2>%s</div>'
        '<div class="card"><h2>أكثر المصادر نشاطًا</h2>%s</div>'
        '<div class="card"><h2>أكثر الأهداف استهدافًا</h2>%s%s</div></div>'
        % (_hbars([(OUTCOME_AR.get(k, k), v) for k, v in outcomes], ov["incidents"]),
           _hbars(ov["attack_types"], ov["incidents"], ATTACK_AR),
           _hbars(ov["top_sources"], ov["incidents"]),
           _hbars(ov["top_targets"], ov["incidents"]), ctx_note) +
        '<div class="card"><h2>جاهزية رفع مستوى الاستقلالية %s</h2>'
        '<p class="sub">المستوى الحالي: L%d. هذه قراءة استرشادية فقط؛ الرفع يبقى قرارًا يدويًا منك (Project.md §6).</p>'
        '<div class="tw"><table><thead><tr><th>الشرط</th><th>الحالة</th><th>القيمة</th></tr></thead>'
        '<tbody>%s</tbody></table></div></div>' % (gate, readiness["level"], checks))


# -- incidents ------------------------------------------------------------- #

FILTER_KEYS = ("outcome", "tier", "attack_type", "ip", "q", "label", "min_score")


def _opts(options, current) -> str:
    return "".join('<option value="%s"%s>%s</option>'
                   % (e(v), " selected" if v == current else "", e(t))
                   for v, t in options)


def incidents(listing: dict, f: dict) -> str:
    form = (
        '<form class="filters" hx-get="/ui/incidents" hx-target="#view" hx-trigger="submit, change from:select">'
        '<select name="origin">%s</select><select name="outcome">%s</select><select name="tier">%s</select>'
        '<select name="attack_type">%s</select><select name="label">%s</select>'
        '<input name="ip" placeholder="IP مصدر/هدف" value="%s">'
        '<input name="q" placeholder="بحث نصي" value="%s">'
        '<input name="min_score" placeholder="أقل درجة (0-1)" value="%s">'
        '<button class="btn btn-go">تصفية</button></form>'
        % (_opts([("", "حي + replay"), ("live", "حي فقط"), ("replay", "replay فقط")], f.get("origin", "")),
           _opts([("", "كل النتائج")] + [(k, v) for k, v in OUTCOME_AR.items()], f.get("outcome", "")),
           _opts([("", "كل الفئات"), ("A", "A"), ("B", "B"), ("C", "C")], f.get("tier", "")),
           _opts([("", "كل الأنواع")] + [(k, v) for k, v in ATTACK_AR.items()], f.get("attack_type", "")),
           _opts([("", "كل التصنيفات"), ("unreviewed", "لم تُراجع"),
                  ("true_positive", "هجوم حقيقي"), ("false_positive", "إنذار كاذب"),
                  ("benign", "نشاط سليم")], f.get("label", "")),
           e(f.get("ip", "")), e(f.get("q", "")), e(f.get("min_score", ""))))
    rows = []
    for r in listing["rows"]:
        iid = e(r["incident_id"])
        who = ("%s ← %s" % (e(r["dst_ip"]), e(r["src_ip"]))) if r["src_ip"] else "—"
        rows.append(
            '<tr><td>%s</td><td><a href="#" hx-get="/ui/incident/%s" hx-target="#drawer"><code>%s</code></a></td>'
            '<td><code>%s</code></td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>'
            % (e(str(r["ts"])[:19]), iid, e(short(r["incident_id"], 16)), who,
               e(ATTACK_AR.get(r["attack_type"], r["attack_type"] or "—")),
               outcome_pill(r["outcome"]), score_bar(r["score"]), e(r["tier"]),
               label_pill(r["label"]), origin_pill(r.get("origin"))))
    table = (empty("لا توجد حوادث مطابقة.") if not rows else
             '<div class="tw"><table><thead><tr><th>الوقت</th><th>الحادثة</th><th>الهدف ← المصدر</th>'
             '<th>النوع</th><th>النتيجة</th><th>الدرجة</th><th>الفئة</th><th>التصنيف</th><th>المصدر</th></tr></thead>'
             '<tbody>%s</tbody></table></div>' % "".join(rows))

    def link(page, text):
        qs = urlencode({**{k: v for k, v in f.items() if v}, "page": page})
        return ('<a href="#" hx-get="/ui/incidents?%s" hx-target="#view">%s</a>' % (e(qs), e(text)))

    pager = ('<div class="pager">%s<span>صفحة %d من %d · %d حادثة</span>%s</div>'
             % (link(listing["page"] - 1, "السابق") if listing["page"] > 1 else "",
                listing["page"], listing["pages"], listing["total"],
                link(listing["page"] + 1, "التالي") if listing["page"] < listing["pages"] else ""))
    export_qs = urlencode({k: v for k, v in f.items() if v and k in ("outcome", "tier", "q", "min_score")})
    return ('<div class="card"><h2>الحوادث</h2><p class="sub">آخر قرار لكل حادثة. اضغط على رقم الحادثة لفتح التفاصيل والتحكم.</p>'
            '%s%s%s<p class="note"><a href="/audit/export.csv?%s">تصدير CSV للنتائج</a></p></div>'
            % (form, table, pager, e(export_qs)))


_WEIGHTS = {"critical": 1.0, "high": 0.85, "medium": 0.65, "low": 0.45}


def score_explanation(full: dict) -> str:
    """Why this score: the real inputs, recorded at decision time."""
    inp = full.get("inputs") or {}
    last = full["decisions"][-1]
    origin = origin_pill(full.get("origin"))
    if not inp:
        return ('<div class="card"><h2>لماذا هذه الدرجة؟ %s</h2>'
                '<p class="note">لم تُسجَّل مدخلات الدرجة لهذه الحادثة (سُجّلت قبل هذا الإصدار).</p></div>' % origin)
    conf = float(inp.get("confidence", 0))
    crit = str(inp.get("criticality", "low"))
    sev = int(inp.get("severity", 1))
    w = _WEIGHTS.get(crit, 0.45)
    base = conf * w * sev / 5
    srcs = "".join('<tr><td><code>%s</code></td><td>%.0f%%</td></tr>' % (e(k), float(v) * 100)
                   for k, v in sorted((inp.get("confidence_sources") or {}).items()))
    pens = inp.get("penalties") or []
    pen_txt = "، ".join("%+.2f" % p for p in pens) if pens else "لا عقوبات"
    return (
        '<div class="card"><h2>لماذا هذه الدرجة؟ %s</h2>'
        '<p class="sub">كل رقم هنا مسجَّل لحظة القرار، وليس مُقدَّرًا لاحقًا.</p>'
        '<table><tbody>'
        '<tr><th>الثقة في الدليل</th><td><b>%.0f%%</b>%s</td></tr>'
        '<tr><th>أهمية الأصل</th><td>%s (وزن <span class="ltr">%.2f</span>)</td></tr>'
        '<tr><th>شدة الهجوم</th><td><span class="ltr">%d / 5</span> · %s</td></tr>'
        '<tr><th>الأساس</th><td><span class="ltr">%.2f × %.2f × %d/5 = %.3f</span></td></tr>'
        '<tr><th>العقوبات</th><td>%s</td></tr>'
        '<tr><th>الدرجة النهائية</th><td><b>%.0f%%</b> · الفئة %s · %s</td></tr>'
        '</tbody></table>%s</div>'
        % (origin, conf * 100,
           (' <span class="note">(اتفاق مصادر مستقلة)</span>' if len(inp.get("confidence_sources") or {}) > 1 else ""),
           e(crit), w, sev, e(inp.get("attack_type")), conf, w, sev, base, e(pen_txt),
           float(last["score"]) * 100, e(last["tier"]), outcome_pill(last["outcome"]),
           ('<table><thead><tr><th>مصدر الدليل</th><th>ثقته</th></tr></thead><tbody>%s</tbody></table>' % srcs) if srcs else ""))


def incident_detail(full: dict, can_annotate: bool) -> str:
    ctx = full["context"]
    head = '<div style="display:flex;justify-content:space-between;align-items:center"><h2><code>%s</code></h2>' \
           '<button class="btn" onclick="closeDrawer()">إغلاق ✕</button></div>' % e(full["incident_id"])
    if ctx:
        chips = "".join('<span class="chip">%s</span>' % e(s) for s in ctx["signals"])
        mitre = "".join('<a class="chip" target="_blank" rel="noopener" href="https://attack.mitre.org/techniques/%s/">%s</a>'
                        % (e(t.replace(".", "/")), e(t)) for t in ctx["mitre"])
        ev = "".join('<li><code>%s</code></li>' % e(x) for x in ctx["evidence"][:25])
        context = (
            '<table><tbody><tr><th>المصدر</th><td><code>%s</code></td></tr><tr><th>الهدف</th><td><code>%s</code></td></tr>'
            '<tr><th>النوع</th><td>%s</td></tr><tr><th>عدد التنبيهات</th><td>%s</td></tr>'
            '<tr><th>من / إلى</th><td><code>%s</code><br><code>%s</code></td></tr>'
            '<tr><th>الإشارات</th><td><div class="chips">%s</div></td></tr>'
            '<tr><th>MITRE ATT&amp;CK</th><td><div class="chips">%s</div><span class="note">مطابقة مرشحة وليست إثباتًا.</span></td></tr></tbody></table>'
            '<details><summary>مراجع الأدلة (%d)</summary><ul>%s</ul><p class="note">مراجع ملف:سطر فقط؛ لا يُخزَّن أي payload.</p></details>'
            % (e(ctx["src_ip"]), e(ctx["dst_ip"]),
               e(ATTACK_AR.get(ctx["attack_type"], ctx["attack_type"] or "—")), e(ctx["alert_count"]),
               e(ctx["first_ts"]), e(ctx["last_ts"]), chips or "—", mitre or "—",
               len(ctx["evidence"]), ev))
    else:
        context = '<p class="empty">لا يوجد سياق مسجل (الحادثة من قبل تشغيل الـ daemon الحي).</p>'

    tl = []
    for d in full["decisions"]:
        events = "".join('<li><code>%s</code> — %s</li>' % (e(x.get("name")), e(x.get("detail")))
                         for x in d["audit_events"] if isinstance(x, dict)) or "<li>لا أحداث</li>"
        rec = d["recommendation"] if isinstance(d["recommendation"], dict) else {}
        tl.append(
            '<div><b>%s</b> %s <span class="note">%s · %s</span><br>'
            'الدرجة %s (الأساس %s) · الفئة %s · السقف: %s<br><span>%s</span>'
            '<br><span class="note">التوصية: %s</span><ul>%s</ul></div>'
            % (e(str(d["ts"])[:19]), outcome_pill(d["outcome"]), e(d["case_id"]), e("#%s" % d["id"]),
               score_bar(d["score"]), "%.0f%%" % (float(d["base_score"]) * 100), e(d["tier"]),
               e(d["cap_applied"]), e(d["would"]),
               e(", ".join("%s=%s" % kv for kv in sorted(rec.items())) or "—"), events))
    notes = "".join('<div class="note"><b>%s</b> %s · %s<br>%s</div>'
                    % (e(str(n["ts"])[:19]), label_pill(n["label"]), e(n["actor"]), e(n["note"]))
                    for n in full["notes"]) or '<p class="note">لا توجد ملاحظات.</p>'
    if can_annotate:
        iid = e(full["incident_id"])
        form = (
            '<form hx-post="/incidents/%s/annotate" hx-target="#drawer" hx-swap="innerHTML">'
            '<select name="label"><option value="">ملاحظة فقط</option><option value="true_positive">هجوم حقيقي</option>'
            '<option value="false_positive">إنذار كاذب</option><option value="benign">نشاط سليم</option></select>'
            '<textarea name="note" rows="3" maxlength="2000" placeholder="ملاحظتك (اختياري)"></textarea>'
            '<button class="btn btn-go" style="margin-top:6px">حفظ</button></form>'
            '<p class="note">تُحفظ في سجل التدقيق ولا تغيّر قرار المحرك ولا تنفذ أي إجراء.</p>' % iid)
    else:
        form = '<p class="note">التعليق غير متاح: لا يوجد سجل تدقيق مربوط.</p>'
    return (score_explanation(full) +
            '<div class="card">%s<p>التصنيف الحالي: %s</p>%s</div>'
            '<div class="card"><h2>مسار القرارات</h2><div class="tl">%s</div></div>'
            '<div class="card"><h2>مراجعة المحلل</h2>%s%s<hr style="border-color:var(--line)">%s</div>'
            % (head, label_pill(full["verdict"]), context, "".join(tl), form, "", notes))


# -- approvals ------------------------------------------------------------- #

def _countdown(deadline_iso: Optional[str]) -> str:
    """Server-side remaining time (the tab refreshes every 15 s)."""
    from datetime import datetime, timezone
    from sentinel.timeutil import parse_iso
    try:
        left = int((parse_iso(str(deadline_iso)) - datetime.now(timezone.utc)).total_seconds())
    except ValueError:
        return "—"
    if left <= 0:
        return "انتهى الوقت"
    return "%d:%02d" % (left // 60, left % 60)


def approvals(pending: list, history: list, engine_attached: bool,
              can_ack: bool = False) -> str:
    if not engine_attached:
        body = ('<div class="warnbox">وضع مشاهدة فقط: لا يوجد محرك قرارات متصل بهذه الواجهة، '
                'لذلك لا توجد موافقات ولا يمكن اتخاذ قرار منها. شغّل <code>sentinel run --ui</code> '
                'ليظهر الطابور هنا.</div>')
    elif not pending:
        body = empty("لا توجد قرارات تنتظر موافقة بشرية الآن.")
    else:
        rows = []
        for p in pending:
            aid = e(p["approval_id"])
            crit = p.get("critical")
            w = p.get("watch") or {}
            acked = w.get("acked_by")
            badge = ""
            if crit:
                badge = ' ' + pill("down", "حرج") + (
                    ' ' + pill("healthy", "استلمها %s" % acked) if acked else "")
            ack_btn = ""
            if crit and can_ack and not acked:
                ack_btn = (' <button class="btn" hx-post="/approvals/%s/ack" '
                           'hx-target="#approvals-result" hx-confirm="تأكيد الاستلام؟ سيتوقف التصرف التلقائي.">'
                           'استلمت الحالة</button>' % aid)
            deadline_cell = ("%s<br><b>باقي %s</b>" % (e(p["deadline"]), e(_countdown(p["deadline"])))
                             if crit else e(p["deadline"]))
            rows.append(
                '<tr><td><a href="#" hx-get="/ui/incident/%s" hx-target="#drawer"><code>%s</code></a>%s</td>'
                '<td><code>%s ← %s</code></td><td>%s</td><td>%s</td><td>%s</td><td>%s</td>'
                '<td><button class="btn btn-ok" hx-post="/approvals/%s/approve" hx-target="#approvals-result" '
                'hx-confirm="اعتماد هذا القرار؟ سيُسجَّل في التدقيق.">اعتماد</button> '
                '<button class="btn btn-no" hx-post="/approvals/%s/deny" hx-target="#approvals-result" '
                'hx-confirm="رفض هذا القرار؟">رفض</button>%s</td></tr>'
                % (aid, e(short(p["approval_id"], 16)), badge, e(p.get("dst_ip") or "—"), e(p.get("src_ip") or "—"),
                   e(ATTACK_AR.get(p.get("attack_type"), p.get("attack_type") or "—")),
                   score_bar(p["score"]), e(p["tier"]), deadline_cell, aid, aid, ack_btn))
        body = ('<div class="tw"><table><thead><tr><th>الحادثة</th><th>الهدف ← المصدر</th><th>النوع</th>'
                '<th>الدرجة</th><th>الفئة</th><th>الموعد النهائي</th><th>القرار</th></tr></thead><tbody>%s</tbody></table></div>'
                '<div id="approvals-result" aria-live="polite"></div>'
                '<p class="note">بعد 15 دقيقة بلا رد يتحول القرار تلقائيًا إلى إشعار فقط.</p>' % "".join(rows))
    hist = "".join(
        '<tr><td>%s</td><td><code>%s</code></td><td>%s</td><td>%s</td></tr>'
        % (e(str(h["ts"])[:19]), e(short(h["incident_id"], 16)), outcome_pill(h["outcome"]), e(h["case_id"]))
        for h in history) or '<tr><td colspan="4" class="note">لا توجد قرارات بشرية سابقة.</td></tr>'
    return ('<div class="card"><h2>الموافقات البشرية</h2><p class="sub">قرارات تنتظرك. الاعتماد يمر عبر نفس '
            'محرك القرارات وسلسلة التحقق (Engine.resolve).</p>%s</div>'
            '<div class="card"><h2>سجل القرارات البشرية</h2><div class="tw"><table><thead><tr><th>الوقت</th>'
            '<th>الحادثة</th><th>النتيجة</th><th>القناة</th></tr></thead><tbody>%s</tbody></table></div></div>'
            % (body, hist))


# -- sources / audit / settings -------------------------------------------- #

def sources(health: list) -> str:
    if not health:
        return empty("لا توجد مصادر.")
    cards = []
    for h in health:
        st = str(h.get("status", "down"))
        live = h.get("source_type") == "live_file"
        cards.append(
            '<div class="kpi"><span>%s</span><b style="font-size:17px"><code>%s</code></b>%s'
            '<small>%s<br>آخر نبضة: %s<br>آخر تنبيه: %s<br>فقد الحزم: %s · أسطر مرفوضة: %s · تدوير: %s</small></div>'
            % (e(h.get("source") or ""), e(h.get("file") or h.get("source")), pill(st, STATUS_AR.get(st, st)),
               "تتبّع مباشر لسجلات المستشعر" if live else "ملف replay · ليس التقاطًا مباشرًا",
               e(h.get("heartbeat_ts")), e(h.get("last_alert_ts")),
               "غير متاح" if h.get("packet_drops") is None else e(h.get("packet_drops")),
               e(h.get("malformed_lines_skipped", 0)), e(h.get("rotations", "—"))))
    return ('<div class="card"><h2>مصادر الأحداث</h2><p class="sub">صحة كل مصدر كما يراها الـ daemon. '
            '"متوقف" تعني أن الملف غير موجود أو أن الـ daemon نفسه لم يحدّث حالته.</p>'
            '<div class="grid">%s</div></div>' % "".join(cards))


def audit(rows: list, f: dict, chain: Optional[dict] = None) -> str:
    form = ('<form class="filters" hx-get="/ui/audit" hx-target="#view">'
            '<select name="outcome">%s</select><select name="case_id">%s</select>'
            '<input name="q" placeholder="بحث" value="%s"><button class="btn btn-go">بحث</button></form>'
            % (_opts([("", "كل النتائج")] + [(k, v) for k, v in OUTCOME_AR.items()], f.get("outcome", "")),
               _opts([("", "كل القنوات"), ("live", "live"), ("pilot", "pilot"), ("ops_ui", "ops_ui"),
                      ("telegram", "telegram")], f.get("case_id", "")), e(f.get("q", ""))))
    body = "".join(
        '<tr><td>%s</td><td>%s</td><td><code>%s</code></td><td>%s</td><td>%s</td><td>%s</td></tr>'
        % (e(r["id"]), e(str(r["ts"])[:19]), e(short(r["incident_id"], 16)), outcome_pill(r["outcome"]),
           score_bar(r["score"]), e(r["case_id"])) for r in rows) or '<tr><td colspan="6" class="note">لا نتائج.</td></tr>'
    verify = ('<button class="btn" hx-get="/ui/audit/verify" hx-target="#chain">تحقق من سلسلة التدقيق</button>'
              '<div id="chain" style="margin-top:10px">%s</div>' % chain_report(chain))
    return ('<div class="card"><h2>سجل التدقيق</h2><p class="sub">كل قرار مسجل بشكل append-only.</p>%s'
            '<div class="tw"><table><thead><tr><th>#</th><th>الوقت</th><th>الحادثة</th><th>النتيجة</th><th>الدرجة</th>'
            '<th>القناة</th></tr></thead><tbody>%s</tbody></table></div>'
            '<p class="note"><a href="/audit/export.csv">تصدير CSV</a></p></div>'
            '<div class="card"><h2>سلامة السجل</h2><p class="sub">يعيد حساب سلسلة SHA-256 ويكشف أي تعديل أو حذف أو إدخال خارجي.</p>%s</div>'
            % (form, body, verify))


def chain_report(rep: Optional[dict]) -> str:
    if rep is None:
        return ""
    if rep["ok"]:
        return ('<div>%s <span class="note">%d إدخال · صفوف قديمة بلا سلسلة: %d</span><br>'
                '<span class="note">رأس السلسلة (سجّله خارج الجهاز): <code>%s</code></span></div>'
                % (pill("healthy", "السلسلة سليمة"), rep["entries"], rep["legacy_unchained"], e(rep["head"])))
    return ('<div>%s<ul>%s</ul></div>'
            % (pill("down", "تم اكتشاف مشكلة"), "".join("<li>%s</li>" % e(p) for p in rep["problems"])))


def settings(view: dict) -> str:
    def kv(rows):
        return '<table><tbody>%s</tbody></table>' % "".join(
            '<tr><th>%s</th><td>%s</td></tr>' % (e(k), v) for k, v in rows)

    lv = {0: "L0 · shadow (توصيات فقط)", 1: "L1 · تنفيذ بعد موافقة", 2: "L2 · آلي للحالات الحرجة", 3: "L3 · آلي كامل"}
    crit = "".join('<span class="chip"><code>%s</code> %s</span>' % (e(a["ip"]), e(a["hostname"]))
                   for a in view["critical_assets"]) or "—"
    env_rows = [(name, pill("healthy" if ok else "degraded", "مضبوط" if ok else "غير مضبوط"))
                for name, ok in view["env"]]
    return (
        '<div class="grid" style="grid-template-columns:repeat(auto-fit,minmax(340px,1fr))">'
        '<div class="card"><h2>الاستقلالية والحدود</h2>%s</div>'
        '<div class="card"><h2>الموقع</h2>%s</div>'
        '<div class="card"><h2>القنوات والتكاملات</h2>%s<p class="note">القيم السرية لا تُعرض؛ فقط هل المتغير مضبوط.</p></div></div>'
        '<p class="note">هذه الصفحة للقراءة فقط. التعديل يتم في ملف الإعدادات ثم إعادة التشغيل، حتى لا يصبح '
        'التحكم عن بعد بالقواعد الأمنية ثغرة.</p>'
        % (kv([("المستوى الحالي", e(lv.get(view["autonomy_level"], view["autonomy_level"]))),
               ("حد الحظر / دقيقة", e(view["limits"]["max_blocks_per_min"])),
               ("حد الحظر / ساعة", e(view["limits"]["max_blocks_per_hour"])),
               ("مدة الحظر الافتراضية", e("%s دقيقة" % view["limits"]["default_ttl_min"])),
               ("الأوضاع", pill("healthy", "dry-run مفروض (G2)"))]),
           kv([("اسم الموقع", e(view["site"])), ("أصول حرجة (G1)", '<div class="chips">%s</div>' % crit),
               ("VLANs مراقبة", e(", ".join(view["monitored_vlans"]))),
               ("خطر التوجيه غير المتماثل", e(view["asymmetric_risk"]))]),
           kv(env_rows + [("Notifiers", e(", ".join(view["notifiers"]) or "—")),
                          ("SIEM", e(view["siem"]))])))
