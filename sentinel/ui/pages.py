"""Ops UI v2 — HTML for every page (Arabic RTL, htmx fragments).

Pure rendering: functions take already-fetched data and return escaped HTML.
No function here touches the store, the engine or the network, so the
security properties live in one place (app.py guards + analytics SELECTs).
Styling is inline because the only unauthenticated asset allowed is the
vendored htmx file (DP2).
"""
from __future__ import annotations

from datetime import datetime, timezone
from html import escape
from typing import Any, Optional
from urllib.parse import urlencode

OUTCOME_AR = {
    "log_only": "تسجيل فقط", "notify_only": "إشعار فقط",
    "human_approval": "بانتظار موافقة", "escalate_human": "تصعيد بشري",
    "report_wait": "تقرير بانتظار المهندس",
    "auto_act": "إجراء آلي", "auto_throttle": "تقييد آلي",
}
ATTACK_AR = {
    "Baseline anomaly": "شذوذ عن خط الأساس",
    "Unmapped event": "حدث غير مصنف",
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
    return pill("healthy", "ملف مراقَب")


def score_bar(score: float) -> str:
    s = max(0.0, min(1.0, float(score)))
    return ('<span class="bar"><i style="width:%.0f%%"></i></span> <b>%.0f%%</b>'
            % (s * 100, s * 100))


def confidence_bar(value) -> str:
    return score_bar(value) if isinstance(value, (int, float)) else e("—")


def short(value: str, n: int = 18) -> str:
    v = str(value or "")
    return v if len(v) <= n else v[:n] + "…"


# -- shell ----------------------------------------------------------------- #

NAV = (("inbox", "مهامي"), ("overview", "نظرة عامة"), ("incidents", "الحوادث"),
       ("approvals", "الموافقات"), ("sources", "المصادر"),
       ("learning", "التعلّم"), ("intel", "MITRE"),
       ("actions", "الإجراءات"), ("audit", "التدقيق"),
       ("reports", "التقارير"), ("ai", "الذكاء الاصطناعي"), ("settings", "الإعدادات"),
       ("guide", "ابدأ هنا"))

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
:root{--bg:#080f1c;--p:#101b2d;--p2:#15243a;--line:#263951;--tx:#eef5ff;--mu:#94a9c3;--bl:#56c5ef;--gr:#52d8a1;--am:#f4bd65;--rd:#ff7585;--space:16px}
body{background:radial-gradient(ellipse at 85% -25%,#133056 0,transparent 46%),var(--bg);min-height:100vh;letter-spacing:.01em}
.top{background:#091421ee;border-bottom:1px solid #2c465d;box-shadow:0 8px 32px #0003}
.top-in{padding-block:14px}.brand{font-size:21px;letter-spacing:.04em;color:#fff}.brand small{letter-spacing:0}
nav button{transition:background .18s,color .18s,transform .18s}nav button:hover{transform:translateY(-1px)}
nav button.on{background:linear-gradient(145deg,#163d59,#17304b);box-shadow:inset 0 0 0 1px #36769a;color:#fff}
.wrap{padding-block:28px}.card{border-color:#2a3e58;border-radius:16px;background:linear-gradient(155deg,#13223a 0%,#101b2d 65%);box-shadow:0 12px 36px #0002}
.card h2{font-size:18px;font-weight:700;letter-spacing:.01em}.card .sub{margin-bottom:18px}
.kpi{min-height:102px;background:linear-gradient(150deg,#182b46,#14243a);border-color:#2a425e;transition:transform .18s,border-color .18s}
.kpi:hover{transform:translateY(-2px);border-color:#3a7197}.kpi b{font-size:29px}.kpi .small-value{font-size:14px;overflow-wrap:anywhere;margin-top:8px}
th{color:#9bbddd;text-transform:none}td{line-height:1.55}tr:hover td{background:#1a2f49}
.btn{transition:background .18s,border-color .18s,transform .18s}.btn:hover{transform:translateY(-1px)}
:is(button,input,select,textarea,a):focus-visible{outline:2px solid var(--bl);outline-offset:3px}
.settings-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(215px,1fr));gap:12px;margin-block:14px}
label{display:block;color:var(--mu);font-size:13px;margin-bottom:12px}label input,label select,label textarea{display:block;color:var(--tx);margin-top:5px}
.inline-form{display:inline-flex;align-items:end;gap:10px;flex-wrap:wrap;margin:8px 12px 8px 0}.inline-form input{max-width:140px}
.bar.wide{display:block;width:100%;height:12px;margin:18px 0}.loading{padding:32px;color:var(--mu);text-align:center}
@media(max-width:750px){.top-in{display:block;padding:12px 18px}.brand{margin-bottom:9px}nav{flex-wrap:nowrap;overflow-x:auto;padding-bottom:5px;scrollbar-width:thin}nav button{white-space:nowrap;padding:8px 11px}.mode{display:flex;gap:5px;flex-wrap:wrap;margin-top:10px}.wrap{padding:18px 12px 40px}.card{padding:15px}.grid{grid-template-columns:repeat(auto-fit,minmax(145px,1fr))}.kpi b{font-size:24px}.cols{grid-template-columns:1fr}}
"""

SHELL = """<!doctype html><html lang="ar" dir="rtl"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Sentinel | لوحة التحكم</title>
<script src="/static/htmx.min.js"></script>%(head_extra)s<style>%(css)s</style></head><body>
<header class="top"><div class="top-in"><div class="brand">Sentinel<small>مركز مراقبة القرارات الأمنية</small></div>
<nav id="nav">%(nav)s</nav><div class="mode" id="mode" hx-get="/ui/mode" hx-trigger="load, refresh, every 20s"></div>%(userbar)s</div></header>
<div class="wrap" id="wrap"><main id="view" hx-get="/ui/inbox" hx-trigger="load, sentinel-update"><p class="loading" role="status">جارٍ تحميل بيانات Sentinel…</p></main>
<aside id="drawer" class="drawer" style="display:none"></aside></div>
<script>
function openDrawer(){document.getElementById('drawer').style.display='block';document.getElementById('wrap').classList.add('has-drawer')}
function closeDrawer(){var d=document.getElementById('drawer');d.style.display='none';d.innerHTML='';document.getElementById('wrap').classList.remove('has-drawer')}
document.getElementById('nav').addEventListener('click',function(ev){var b=ev.target.closest('button');if(!b)return;
document.querySelectorAll('#nav button').forEach(function(x){x.classList.remove('on')});b.classList.add('on');closeDrawer()});
document.body.addEventListener('htmx:afterSwap',function(ev){if(ev.target.id==='drawer'){openDrawer()}});
document.body.addEventListener('htmx:configRequest',function(ev){var t=sessionStorage.getItem('sentinel-token');if(t)ev.detail.headers['X-Sentinel-Token']=t;var c=document.querySelector('meta[name=csrf-token]');if(c)ev.detail.headers['X-CSRF-Token']=c.content});
document.body.addEventListener('htmx:responseError',function(ev){var st=ev.detail.xhr.status;if(st===401&&document.querySelector('meta[name=csrf-token]')){location.href='/login';return}var msg=st===403?'ليست لديك صلاحية لهذا الإجراء.':'تعذر تحميل البيانات. أعد المحاولة.';if(ev.target.id==='view'){ev.target.innerHTML='<p class="warnbox" role="alert">'+msg+'</p>'}else{alert(msg)}});
document.querySelector('#nav button').classList.add('on');
var activePage='/ui/inbox';
document.getElementById('nav').addEventListener('click',function(ev){var b=ev.target.closest('button[hx-get]');if(b){activePage=b.getAttribute('hx-get');document.getElementById('view').setAttribute('hx-get',activePage)}});
async function liveFeed(){try{var r=await fetch('/ui/events',{headers:{'X-Sentinel-Token':sessionStorage.getItem('sentinel-token')||''}});if(!r.ok)return;var reader=r.body.getReader(),decoder=new TextDecoder(),buf='';while(true){var x=await reader.read();if(x.done)break;buf+=decoder.decode(x.value,{stream:true});var parts=buf.split('\\n\\n');buf=parts.pop();for(var part of parts){if(part.startsWith('data:')){htmx.trigger('#view','sentinel-update');htmx.trigger('#mode','refresh')}}}}catch(e){}setTimeout(liveFeed,3000)}
liveFeed();
</script></body></html>"""


ROLE_AR = {"viewer": "مشاهد", "analyst": "محلل", "admin": "مدير"}


def shell(user: Optional[dict] = None) -> str:
    items = list(NAV)
    if user and user.get("role") == "admin":
        items.insert(-1, ("users", "المستخدمون"))
    nav = "".join(
        '<button hx-get="/ui/%s" hx-target="#view" hx-swap="innerHTML">%s</button>'
        % (k, e(v)) for k, v in items)
    head_extra, userbar = "", ""
    if user:
        head_extra = '<meta name="csrf-token" content="%s">' % e(user["csrf"])
        userbar = ('<div class="who" style="display:flex;gap:8px;align-items:center">'
                   '<span class="pill">%s · %s</span>'
                   '<button class="btn" hx-post="/auth/logout" hx-swap="none">خروج</button>'
                   '</div>' % (e(user["name"]), e(ROLE_AR.get(user["role"], user["role"]))))
    return SHELL % {"css": CSS, "nav": nav, "head_extra": head_extra,
                    "userbar": userbar}


def login() -> str:
    return '''<!doctype html><html lang="ar" dir="rtl"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Sentinel | دخول</title>
<style>:root{color-scheme:dark}body{font:16px/1.6 Tahoma,sans-serif;background:#080f1c;color:#eef5ff;
min-height:100vh;display:grid;place-items:center;margin:0}.box{width:min(92vw,390px);padding:32px;
border:1px solid #2a425e;border-radius:18px;background:#13223a}h1{margin:0 0 8px}
p{color:#a5b8cc}input,button{display:block;width:100%;box-sizing:border-box;margin-top:16px;padding:12px;
border-radius:9px;font:inherit}input{background:#0b1728;border:1px solid #42627e;color:white}
button{background:#176183;border:0;color:white;cursor:pointer}button:focus-visible,input:focus-visible{
outline:2px solid #56c5ef;outline-offset:2px}</style></head><body><div class="box">
<h1>Sentinel</h1><p>أدخل رمز تشغيل لوحة العمليات. يبقى الرمز في هذه التبويبة فقط.</p>
<form id="login"><label for="token">رمز الوصول</label><input id="token" type="password" required autofocus>
<button>دخول</button></form><p id="error" role="alert"></p></div>
<script>document.getElementById('login').addEventListener('submit',async function(ev){ev.preventDefault();
var token=document.getElementById('token').value;var error=document.getElementById('error');
try{var response=await fetch('/',{headers:{'X-Sentinel-Token':token}});
if(!response.ok){error.textContent='رمز غير صحيح أو الخدمة غير متاحة.';return}
sessionStorage.setItem('sentinel-token',token);var html=await response.text();
document.open();document.write(html);document.close()}
catch(e){error.textContent='تعذر الاتصال بالخدمة.'}});</script></body></html>'''


def mode_badge(mode: dict) -> str:
    if not mode.get("available"):
        return pill("degraded", "لا توجد حالة تشغيل حية")
    if not mode.get("fresh"):
        return pill("down", "الـ daemon متوقف أو حالته متأخرة")
    state = mode.get("mode")
    if state == "learning":
        learning = mode.get("learning") or {}
        total = int(learning.get("learning_days", 14)) + int(learning.get("extend_days", 0))
        phase = "تعلّم %s/%s يوم" % (e(learning.get("observed_days", "—")), total)
    elif state == "active":
        phase = "Active"
    elif state == "live_shadow":
        phase = "حي · shadow"
    elif state == "live_enforcing":
        phase = "Active"
    else:
        phase = "الوضع غير محدد"
    enforcement = mode.get("enforcement") or {}
    dry = enforcement.get("dry_run")
    posture = ("dry-run" if dry is True else
               "تنفيذ فعلي" if dry is False else "حالة التنفيذ غير معروفة")
    sources = mode.get("sources") or []
    unhealthy = sum(s.get("status") != "healthy" for s in sources)
    health = "المصادر %s/%s متأثرة" % (unhealthy, len(sources)) if sources else "لا مصادر"
    channels = (mode.get("notifications") or {}).get("channels")
    notices = "قنوات التنبيه %s" % e(channels) if channels is not None else "قنوات غير معروفة"
    return " ".join((pill("healthy" if state != "learning" else "degraded", phase),
                     pill("degraded" if dry else "down", posture),
                     pill("healthy" if unhealthy == 0 and sources else "degraded", health),
                     pill("healthy" if channels else "degraded", notices)))


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


def overview(ov: dict, readiness: dict, kp: dict, pending: int,
             recent: list | None = None, learning: dict | None = None) -> str:
    def kpi(title, value, sub="", tone=""):
        return ('<div class="kpi %s"><span>%s</span><b>%s</b><small>%s</small></div>'
                % (tone, e(title), e(value), e(sub)))

    fp = ov["analyst_fp_rate"]
    lat = ov["latency"]
    lat_val = "—" if lat["median_s"] is None else "%s ث" % lat["median_s"]
    lat_sub = ("الوسيط من أول دليل إلى القرار · %d حادثة من ملفات المراقبة · p90 %s ث"
               % (lat["n"], lat["p90_s"])) if lat["n"] else \
        "لا توجد حوادث من ملفات المراقبة بعد؛ لا يُحسب رقم بدل الأرقام الحقيقية"
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
                              ("live", "ملفات مراقبة", oc["live"]),
                              ("replay", "replay", oc["replay"])))
    if ov["origin"] == "replay" or (not ov["origin"] and oc["replay"]):
        banner = ('<div class="warnbox" style="margin-bottom:12px">هذه الأرقام تشمل حوادث <b>replay</b>: '
                  'ملفات مسجلة أو بيانات اصطناعية من الـ pilot. ملفات المراقبة نفسها قد تحتوي محاكاة؛ '
                  'تحقق من مصدر السجل قبل اعتبار أي حادثة حركة شبكة حقيقية.</div>')
    elif not oc["live"] and not oc["replay"]:
        banner = '<div class="warnbox" style="margin-bottom:12px">لا توجد أي حوادث مسجلة بعد.</div>'
    else:
        banner = ""
    origin_bar = '<div style="margin-bottom:12px">%s</div>%s' % (sw, banner)
    feed = "".join('<tr><td>%s</td><td>%s</td><td>%s</td><td><code>%s</code></td>'
                   '<td>%s</td><td>%s</td></tr>' %
                   (e(ATTACK_AR.get(r.get("attack_type"), r.get("attack_type") or "—")),
                    confidence_bar(r.get("confidence")),
                    e(", ".join(r.get("mitre") or []) or "—"),
                    e(r.get("src_ip")), e(r.get("tier")), outcome_pill(r["outcome"]))
                   for r in (recent or []))
    learning = learning or {}
    daily = learning.get("daily_volume") or {}
    baseline = learning.get("baseline_daily_mean")
    today_count = daily.get(datetime.now(timezone.utc).date().isoformat())
    traffic = ('<div class="card"><h2>الحركة مقابل خط الأساس</h2>'
               '<p class="sub">أحداث السجلات المرصودة اليوم مقابل متوسط الأيام السابقة؛ ليست بايتات الشبكة.</p>'
               '<div class="grid"><div class="kpi"><span>اليوم</span><b>%s</b></div>'
               '<div class="kpi"><span>متوسط أيام الأساس السابقة</span><b>%s</b></div></div></div>' %
               (e(today_count), e(baseline)))
    links = sorted({(str(r.get("src_ip")), str(r.get("dst_ip")))
                    for r in (recent or []) if r.get("src_ip") and r.get("dst_ip")})[:8]
    network = ('<div class="card"><h2>خريطة المصادر والأهداف</h2>'
               '<p class="sub">علاقات IP المسجلة في آخر الحوادث؛ لا استدلال جغرافي.</p><div class="chips">%s</div></div>' %
               ("".join('<span class="chip"><code>%s → %s</code></span>' %
                        (e(src), e(dst)) for src, dst in links) or e("لا علاقات مرصودة")))
    return (
        origin_bar +
        '<div class="grid">%s</div>' % kpis +
        '<div class="card"><h2>الأحداث الأمنية الأخيرة</h2><p class="sub">آخر حوادث من سجل التدقيق؛ يتحدث عند وصول قرار جديد.</p>'
        '<div class="tw"><table><thead><tr><th>الهجوم</th><th>الثقة</th><th>MITRE</th>'
        '<th>المصدر</th><th>الفئة</th><th>الحالة</th></tr></thead><tbody>%s</tbody></table></div></div>' %
        (feed or '<tr><td colspan="6">لا حوادث بعد.</td></tr>') + traffic + network +
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
        % (_opts([("", "ملفات + replay"), ("live", "ملفات مراقبة"), ("replay", "replay فقط")], f.get("origin", "")),
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
        technique = ", ".join(r.get("mitre") or [])
        attack_label = e(ATTACK_AR.get(r["attack_type"], r["attack_type"] or "—"))
        if technique:
            attack_label += "<br><code>" + e(technique) + "</code>"
        rows.append(
            '<tr><td>%s</td><td><a href="#" hx-get="/ui/incident/%s" hx-target="#drawer"><code>%s</code></a></td>'
            '<td><code>%s</code></td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>'
            % (e(str(r["ts"])[:19]), iid, e(short(r["incident_id"], 16)), who,
               attack_label,
               outcome_pill(r["outcome"]), confidence_bar(r["confidence"]), e(r["tier"]),
               label_pill(r["label"]), origin_pill(r.get("origin"))))
    table = (empty("لا توجد حوادث مطابقة.") if not rows else
             '<div class="tw"><table><thead><tr><th>الوقت</th><th>الحادثة</th><th>الهدف ← المصدر</th>'
             '<th>النوع</th><th>النتيجة</th><th>الثقة</th><th>الفئة</th><th>التصنيف</th><th>المصدر</th></tr></thead>'
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
    if not isinstance(inp.get("confidence"), (int, float)):
        return ('<div class="card"><h2>تفسير الدرجة</h2>'
                '<p class="note">الثقة الأصلية غير مسجلة لهذه الحادثة.</p></div>')
    conf = float(inp["confidence"])
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
    head = ('<div style="display:flex;justify-content:space-between;align-items:center;gap:8px">'
            '<h2><code>%s</code></h2><span><a class="btn" target="_blank" rel="noopener" '
            'href="/incidents/%s/report">تقرير للطباعة / PDF</a> '
            '<button class="btn" onclick="closeDrawer()">إغلاق ✕</button></span></div>'
            % (e(full["incident_id"]), e(full["incident_id"])))
    if ctx:
        chips = "".join('<span class="chip">%s</span>' % e(s) for s in ctx["signals"])
        mitre = "".join('<a class="chip" target="_blank" rel="noopener" href="https://attack.mitre.org/techniques/%s/">%s</a>'
                        % (e(t.replace(".", "/")), e(t)) for t in ctx["mitre"])
        ev = "".join('<li><code>%s</code></li>' % e(x if isinstance(x, str) else x.get("ref"))
                     for x in ctx["evidence"][:25])
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
    return (incident_story(full) + ai_opinion(full.get("ai") or []) + score_explanation(full) +
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
            if can_ack and w and not acked:
                ack_btn = (' <button class="btn" hx-post="/approvals/%s/ack" '
                           'hx-target="#approvals-result" hx-confirm="تأكيد الاستلام؟ سيتوقف التصرف التلقائي.">'
                           'استلمت الحالة</button>' % aid)
            deadline_cell = "%s<br><b>باقي %s</b>" % (e(p["deadline"]), e(_countdown(p["deadline"])))
            technique = ", ".join(p.get("mitre") or [])
            attack_label = e(ATTACK_AR.get(p.get("attack_type"), p.get("attack_type") or "—"))
            if technique:
                attack_label += "<br><code>" + e(technique) + "</code>"
            modify_form = (
                '<form hx-post="/approvals/%s/modify" hx-target="#approvals-result" '
                'hx-confirm="تعديل الخطة واعتمادها؟">'
                '<select name="action" aria-label="الإجراء البديل">'
                '<option value="throttle_src">تقييد المصدر</option>'
                '<option value="block_ip_temp">حظر مؤقت</option>'
                '<option value="notify_only">إشعار فقط</option></select>'
                '<input name="ttl_minutes" type="number" min="1" max="60" value="15" '
                'aria-label="مدة الإجراء بالدقائق">'
                '<button class="btn" type="submit">تعديل واعتماد</button></form>' % aid)
            rows.append(
                '<tr><td><a href="#" hx-get="/ui/incident/%s" hx-target="#drawer"><code>%s</code></a>%s</td>'
                '<td><code>%s ← %s</code></td><td>%s</td><td>%s</td><td>%s</td><td>%s</td>'
                '<td><button class="btn btn-ok" hx-post="/approvals/%s/approve" hx-target="#approvals-result" '
                'hx-confirm="اعتماد هذا القرار؟ سيُسجَّل في التدقيق.">اعتماد</button> '
                '<button class="btn btn-no" hx-post="/approvals/%s/deny" hx-target="#approvals-result" '
                'hx-confirm="رفض هذا القرار؟">رفض</button>%s%s</td></tr>'
                % (aid, e(short(p["approval_id"], 16)), badge, e(p.get("dst_ip") or "—"), e(p.get("src_ip") or "—"),
                   attack_label, confidence_bar(p["confidence"]), e(p["tier"]),
                   deadline_cell, aid, aid, ack_btn, modify_form))
        body = ('<div class="tw"><table><thead><tr><th>الحادثة</th><th>الهدف ← المصدر</th><th>النوع</th>'
                '<th>الثقة</th><th>الفئة</th><th>الموعد النهائي</th><th>القرار</th></tr></thead><tbody>%s</tbody></table></div>'
                '<div id="approvals-result" aria-live="polite"></div>'
                '<p class="note">بعد المهلة تُراجع خطة الاستجابة المضبوطة؛ التنفيذ الجاف بلا تأثير على الشبكة.</p>' % "".join(rows))
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
            '<p class="note"><a href="/audit/export.csv">تصدير CSV</a> · '
            '<a href="/audit/export.json">تصدير JSON</a></p></div>'
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


def settings(view: dict, editable: bool = False, saved: bool = False) -> str:
    def kv(rows):
        return '<table><tbody>%s</tbody></table>' % "".join(
            '<tr><th>%s</th><td>%s</td></tr>' % (e(k), v) for k, v in rows)

    lv = {0: "L0 · shadow (توصيات فقط)", 1: "L1 · تنفيذ بعد موافقة", 2: "L2 · آلي للحالات الحرجة", 3: "L3 · آلي كامل"}
    crit = "".join('<span class="chip"><code>%s</code> %s</span>' % (e(a["ip"]), e(a["hostname"]))
                   for a in view["critical_assets"]) or "—"
    env_rows = [(name, pill("healthy" if ok else "degraded", "مضبوط" if ok else "غير مضبوط"))
                for name, ok in view["env"]]
    dry = view.get("dry_run")
    dry_text = "dry-run مفعّل" if dry is True else "تنفيذ فعلي" if dry is False else "حالة التشغيل غير متاحة"
    policy = view.get("policy") or {}
    summary = (
        '<div class="grid" style="grid-template-columns:repeat(auto-fit,minmax(340px,1fr))">'
        '<div class="card"><h2>الاستقلالية والحدود</h2>%s</div>'
        '<div class="card"><h2>الموقع</h2>%s</div>'
        '<div class="card"><h2>القنوات والتكاملات</h2>%s<p class="note">القيم السرية لا تُعرض؛ فقط هل المتغير مضبوط.</p></div></div>'
        '<p class="note">تطبيق تغييرات الإعدادات يتطلب إعادة تشغيل Sentinel.</p>'
        % (kv([("المستوى الحالي", e(lv.get(view["autonomy_level"], view["autonomy_level"]))),
               ("حد الحظر / دقيقة", e(view["limits"]["max_blocks_per_min"])),
               ("حد الحظر / ساعة", e(view["limits"]["max_blocks_per_hour"])),
               ("مدة الحظر الافتراضية", e("%s دقيقة" % view["limits"]["default_ttl_min"])),
               ("الوضع", pill("healthy" if dry else "degraded", dry_text)),
               ("الثقة: تلقائي / موافقة / تقرير", e(" / ".join(str(policy.get(k, "—")) for k in
                   ("auto_act_threshold", "human_approval_threshold", "report_threshold")))),
               ("مهلة الموافقة / التقرير", e("%s / %s دقيقة" % (
                   policy.get("approval_timeout_minutes", 15), policy.get("report_timeout_minutes", 30))))]),
           kv([("اسم الموقع", e(view["site"])), ("أصول حرجة (G1)", '<div class="chips">%s</div>' % crit),
               ("عناوين محمية", e(", ".join(view.get("protected_ips") or []) or "—")),
               ("VLANs مراقبة", e(", ".join(view["monitored_vlans"]))),
               ("خطر التوجيه غير المتماثل", e(view["asymmetric_risk"]))]),
           kv(env_rows + [("Notifiers", e(", ".join(view["notifiers"]) or "—")),
                          ("SIEM", e(view["siem"]))])))
    if not editable:
        return summary + '<p class="note">ملف التهيئة غير مربوط بهذه الواجهة؛ لا يمكن حفظ التغييرات هنا.</p>'
    defaults = {"auto_act_threshold": 0.95, "human_approval_threshold": 0.80,
                "report_threshold": 0.50, "approval_timeout_minutes": 15,
                "report_timeout_minutes": 30, "max_blocks_per_min": 5,
                "max_blocks_per_hour": 20, "default_ttl_min": 30}
    fields = "".join(
        '<label>%s<input name="%s" type="%s" step="%s" value="%s" required></label>' %
        (e(title), e(key), typ, step,
         e((policy if key in policy else view["limits"]).get(key, defaults[key])))
        for title, key, typ, step in (
            ("عتبة التنفيذ الآلي", "auto_act_threshold", "number", "0.01"),
            ("عتبة الموافقة", "human_approval_threshold", "number", "0.01"),
            ("عتبة التقرير", "report_threshold", "number", "0.01"),
            ("مهلة الموافقة بالدقائق", "approval_timeout_minutes", "number", "1"),
            ("مهلة التقرير بالدقائق", "report_timeout_minutes", "number", "1"),
            ("حد الحظر في الدقيقة", "max_blocks_per_min", "number", "1"),
            ("حد الحظر في الساعة", "max_blocks_per_hour", "number", "1"),
            ("مدة الحظر الافتراضية بالدقائق", "default_ttl_min", "number", "1")))
    import json
    form = ('<div class="card"><h2>تعديل الإعدادات</h2>'
            '<form hx-post="/settings/save" hx-target="#view">'
            '<div class="settings-grid">%s</div>'
            '<label>العناوين المحمية، بفواصل<input name="protected_ips" value="%s"></label>'
            '<label>قنوات التنبيه JSON، بأسماء متغيرات البيئة فقط'
            '<textarea name="notifiers" rows="4">%s</textarea></label>'
            '<button class="btn btn-go">احفظ بعد التحقق</button></form></div>' %
            (fields, e(", ".join(view.get("protected_ips") or [])),
             e(json.dumps(view.get("notifier_configs") or [], ensure_ascii=False))))
    toggle = ('<div class="card"><h2>وضع التنفيذ</h2>'
              '<p class="sub">الوضع الحالي يظهر في الأعلى. التغيير المحفوظ لا يسري حتى إعادة التشغيل.</p>'
              '<form hx-post="/settings/dry-run" hx-target="#view" class="inline-form">'
              '<input type="hidden" name="dry_run" value="on">'
              '<button class="btn btn-ok">احفظ وضع المحاكاة</button></form>'
              '<form hx-post="/settings/dry-run" hx-target="#view" class="inline-form" '
              'hx-confirm="تأكيد إيقاف المحاكاة بعد إعادة التشغيل؟ قد تُنفذ إجراءات على الشبكة الحية.">'
              '<input type="hidden" name="dry_run" value="off">'
              '<button class="btn btn-no">إيقاف المحاكاة بعد إعادة التشغيل</button></form></div>')
    notice = '<p class="warnbox">حُفظت الإعدادات. أعد تشغيل Sentinel لتطبيقها.</p>' if saved else ''
    return notice + summary + form + toggle


def learning(profile: dict) -> str:
    total = profile["learning_days"] + profile["extend_days"]
    done = profile["observed_days"]
    features = profile.get("features") or {}
    rows = "".join(
        '<tr><th>%s</th><td>%s</td><td>%s</td></tr>' %
        (e(name), e(len(values)), e(sum(values.values())))
        for name, values in features.items())
    forms = (
        '<form hx-post="/learning/extend" hx-target="#view" class="inline-form">'
        '<label>مدّ فترة التعلّم بالأيام <input name="days" type="number" min="1" max="365" value="1" required></label>'
        '<button class="btn">مدّ الفترة</button></form>'
        '<form hx-post="/learning/mode" hx-target="#view" class="inline-form" '
        'hx-confirm="تغيير وضع التعلّم؟ قد يسمح وضع Active بتنفيذ إجراءات إذا أوقفت المحاكاة لاحقًا.">'
        '<label>تغيير الوضع <select name="mode"><option value="auto">تلقائي</option>'
        '<option value="learning">تعلّم</option><option value="active">Active</option></select></label>'
        '<button class="btn btn-go">احفظ الوضع</button></form>')
    return ('<div class="card"><h2>مرحلة التعلّم</h2><p class="sub">ملف أساس محفوظ وقابل للتصدير.</p>'
            '<div class="grid"><div class="kpi"><span>الوضع الحالي</span><b>%s</b></div>'
            '<div class="kpi"><span>أيام الرصد</span><b>%s / %s</b></div>'
            '<div class="kpi"><span>موعد التحول</span><b class="small-value">%s</b></div></div>'
            '<p class="note">بدأ: %s · تجاوز السعة: %s · سياسة التحول: %s</p>'
            '<div class="bar wide"><i style="width:%.1f%%"></i></div>'
            '<div class="tw"><table><thead><tr><th>خاصية الأساس</th><th>قيم مختلفة</th><th>رصد</th></tr></thead>'
            '<tbody>%s</tbody></table></div>%s'
            '<p><a href="/learning/export.json">تنزيل الأساس JSON</a></p></div>' %
            (e(profile["mode"]), e(done), e(total), e(profile["active_at"]),
             e(profile["started_at"]), e(profile["overflow"]), e(profile["override"]),
             min(100, 100 * done / total), rows, forms))


def intel(data: dict) -> str:
    rows = "".join('<tr><td><code>%s</code></td><td>%s</td><td>%s</td></tr>' %
                   (e(item.get("id")), e(item.get("name")),
                    e(", ".join(item.get("tactics") or [])))
                   for item in data["techniques"])
    cves = "".join('<code class="chip">%s</code> ' % e(c) for c in data["cves"])
    return ('<div class="card"><h2>MITRE ATT&amp;CK و CVE</h2>'
            '<p class="sub">مطابقة محلية؛ التحديث يتم في الخلفية بواسطة الـ daemon.</p>'
            '<div class="grid"><div class="kpi"><span>تقنيات محفوظة</span><b>%s</b></div>'
            '<div class="kpi"><span>مدخلات CVE محفوظة</span><b>%s</b></div>'
            '<div class="kpi"><span>آخر تحديث</span><b class="small-value">%s</b></div></div>'
            '<p class="note">المصدر: %s</p>'
            '<form class="filters" hx-get="/ui/intel" hx-target="#view">'
            '<input name="q" value="%s" placeholder="ابحث بالمعرّف أو الاسم"><button class="btn">بحث</button></form>'
            '<div class="tw"><table><thead><tr><th>المعرّف</th><th>التقنية</th><th>التكتيكات</th></tr></thead>'
            '<tbody>%s</tbody></table></div>%s</div>' %
            (e(data["technique_count"]), e(data["cve_count"]),
             e(data["refreshed_at"]), e(data["source"] or "مطابقة محلية؛ الكتالوج لم يُزامَن"),
             e(data["q"]), rows or '<tr><td colspan="3">لا نتائج محفوظة.</td></tr>',
             '<p>نتائج CVE: %s</p>' % cves if cves else ''))


def actions(rows: list, rollbacks: list, active: list, connected: bool) -> str:
    current = "".join(
        '<tr><td>%s</td><td><code>%s</code></td><td>%s</td><td>'
        '<form hx-post="/actions/rollback" hx-target="#view" '
        'hx-confirm="إرجاع هذا الإجراء الآن؟">'
        '<input type="hidden" name="action" value="%s">'
        '<input type="hidden" name="target" value="%s">'
        '<button class="btn btn-no">إرجاع</button></form></td></tr>' %
        (e(a.get("action")), e(a.get("target")), e(a.get("expires")),
         e(a.get("action")), e(a.get("target"))) for a in active)
    history = "".join('<tr><td>%s</td><td>%s</td><td><code>%s</code></td><td>%s</td><td>%s</td></tr>' %
                      (e(r[1]), e(r[3]), e(r[4]), e(r[6]),
                       "نعم" if r[7] else "لا") for r in rows)
    rolled = "".join('<tr><td>%s</td><td>%s</td><td>%s</td></tr>' %
                     (e(r[0]), e(r[1]), "نجح" if r[2] else "فشل") for r in rollbacks)
    return ('<div class="card"><h2>إجراءات نشطة</h2>%s<div class="tw"><table><tbody>%s</tbody></table></div></div>'
            '<div class="card"><h2>سجل الاستجابة</h2><div class="tw"><table><thead><tr>'
            '<th>الوقت</th><th>الإجراء</th><th>المصدر</th><th>النتيجة</th><th>نُفذ</th></tr></thead>'
            '<tbody>%s</tbody></table></div></div>'
            '<div class="card"><h2>عمليات الرجوع</h2><div class="tw"><table><tbody>%s</tbody></table></div></div>' %
            ('' if connected else '<p class="warnbox">المشغّل غير متصل؛ عرض السجل فقط.</p>',
             current or '<tr><td>لا إجراءات نشطة.</td></tr>',
             history or '<tr><td colspan="5">لا إجراءات مسجلة.</td></tr>',
             rolled or '<tr><td>لا عمليات رجوع.</td></tr>'))


def reports(report: Optional[dict]) -> str:
    summary = ('<p class="note">آخر تقرير: %s · حوادث في التقرير: %s · إجراءات: %s</p>' %
               (e(report["generated_at"]), e(len(report["incidents"])),
                e(len(report["actions"])))) if report else empty("لم يُنشأ تقرير بعد.")
    return ('<div class="card"><h2>التقارير</h2><p class="sub">لقطة من قاعدة التدقيق وحالة التشغيل وقت الطلب.</p>'
            '<form hx-post="/reports/generate" hx-target="#view"><button class="btn btn-go">أنشئ تقريرًا الآن</button></form>'
            '%s%s</div>' % (summary, '<p><a href="/reports/latest.json">تنزيل JSON</a></p>' if report else ''))


def guide() -> str:
    sections = (
        ("1 · ما هو Sentinel؟", "سجلات Zeek وSuricata ← تعلّم 14 يومًا ← Active: كشف ومقارنة مع MITRE ← تسجيل أو موافقة أو إجراء محمي حسب الثقة."),
        ("2 · التشغيل", "محليًا: python -m sentinel --config config.yaml run --capture-dir capture --ui. Docker: docker compose up --build -d. افتح /login وأدخل SENTINEL_OPS_UI_TOKEN."),
        ("3 · ربط الشبكة", "ضع eve.json وconn.log وdns.log وssl.log وnotice.log في مجلد capture. على Linux اضبط CAPTURE_IFACE وCOMPOSE_PROFILES=capture بعد تجهيز SPAN/TAP. اضبط site.protected_ips في YAML."),
        ("4 · تجربة آمنة", "أبقِ dry-run ظاهرًا. شغّل python -m sentinel.simulation scan --capture-dir capture ثم brute وddos وanomaly. الشذوذ يحتاج خط أساس مكتملًا؛ ليست هناك حزم مرسلة."),
        ("5 · يوم المهندس", "راجع الحوادث وMITRE، ثم اعتمد أو ارفض أو عدّل الموافقات. راجع الإجراءات والرجوع، تحقق من التدقيق، وأنشئ تقريرًا."),
        ("6 · قبل التشغيل الفعلي", "راجع 14 يومًا من البيانات، المصادر، قائمة الحماية، قنوات الإشعار، المهلات والرجوع. إيقاف المحاكاة يتطلب تأكيدًا وإعادة تشغيل؛ ابدأ بشبكة اختبار."),
        ("7 · الأعطال الشائعة", "لا دخول: افحص الرمز والمنفذ. لا أحداث: افحص الملفات والمصادر. لا MITRE: افحص الكتالوج. لا شذوذ: أكمل الأساس. لا تنفيذ: راجع مرحلة التعلّم وL0 وdry-run."))
    return ('<div class="card"><h2>ابدأ مع Sentinel</h2>'
            '<p class="sub">دليل التشغيل الكامل والأوامر التفصيلية وحلول 10 مشكلات في GUIDE.md.</p>'
            '<div class="cols">%s</div></div>' %
            "".join('<section class="kpi"><h2>%s</h2><p>%s</p></section>' %
                    (e(title), e(body)) for title, body in sections))


# -- accounts mode: login / first-login setup / user administration ------------

_AUTH_CSS = """:root{color-scheme:dark}body{font:16px/1.6 Tahoma,sans-serif;background:#080f1c;color:#eef5ff;
min-height:100vh;display:grid;place-items:center;margin:0}.box{width:min(92vw,430px);padding:30px;
border:1px solid #2a425e;border-radius:18px;background:#13223a}h1{margin:0 0 6px}p{color:#a5b8cc}
label{display:block;margin-top:14px;color:#c9d7e8;font-size:14px}
input,button{display:block;width:100%;box-sizing:border-box;margin-top:6px;padding:12px;border-radius:9px;font:inherit}
input{background:#0b1728;border:1px solid #42627e;color:white}
button{margin-top:20px;background:#176183;border:0;color:white;cursor:pointer}
.err{background:#40232c;border:1px solid #8a3a4a;color:#ffd0d7;padding:10px 12px;border-radius:9px}
.key{direction:ltr;font:15px Consolas,monospace;background:#0b1728;border:1px dashed #42627e;padding:10px;
border-radius:9px;word-break:break-all;user-select:all;text-align:center;letter-spacing:2px}
ol{padding-inline-start:20px;color:#c9d7e8}a{color:#56c5ef}
:is(button,input,a):focus-visible{outline:2px solid #56c5ef;outline-offset:2px}"""


def login_accounts(error: str = "", need_code: bool = False, username: str = "",
                   first_run: bool = False) -> str:
    note = ""
    if first_run:
        note = ('<p class="err">لا يوجد أي حساب بعد. أنشئ أول مدير من السيرفر:<br>'
                '<code style="direction:ltr;display:block">sentinel ctl user add NAME --role admin</code></p>')
    code_field = ('<label for="code">رمز التحقق (6 أرقام من تطبيق Authenticator)</label>'
                  '<input id="code" name="code" inputmode="numeric" autocomplete="one-time-code"'
                  ' pattern="[0-9 ]{6,7}" required autofocus>') if need_code else ""
    return ('<!doctype html><html lang="ar" dir="rtl"><head><meta charset="utf-8">'
            '<meta name="viewport" content="width=device-width,initial-scale=1">'
            '<title>Sentinel | دخول</title><style>' + _AUTH_CSS + '</style></head><body>'
            '<div class="box"><h1>Sentinel</h1><p>تسجيل دخول المشغّلين. كل دخول وخروج يُسجَّل في سجل التدقيق.</p>'
            + note + ('<p class="err" role="alert">%s</p>' % e(error) if error else "") +
            '<form method="post" action="/auth/login" autocomplete="on">'
            '<label for="username">اسم المستخدم</label>'
            '<input id="username" name="username" autocomplete="username" required value="%s"%s>'
            '<label for="password">كلمة المرور</label>'
            '<input id="password" name="password" type="password" autocomplete="current-password" required>'
            % (e(username) if username else "", "" if need_code else " autofocus")
            + code_field + '<button>دخول</button></form></div></body></html>')


def account_setup(*, username: str, secret: str, uri: str, csrf: str,
                  must_change: bool, mfa_enabled: bool, error: str = "") -> str:
    grouped = " ".join(secret[i:i + 4] for i in range(0, len(secret), 4))
    pw = ('<label for="np">كلمة مرور جديدة (12 حرفًا على الأقل)</label>'
          '<input id="np" name="new_password" type="password" autocomplete="new-password" minlength="12" required>'
          '<label for="cp">تأكيد كلمة المرور</label>'
          '<input id="cp" name="confirm_password" type="password" autocomplete="new-password" minlength="12" required>'
          ) if must_change else ""
    steps = "" if mfa_enabled else (
        '<ol><li>افتح Google Authenticator أو Microsoft Authenticator على الموبايل.</li>'
        '<li>اختر <b>إضافة حساب ← إدخال مفتاح الإعداد</b> واكتب المفتاح ده (نوع: حسب الوقت):</li></ol>'
        '<div class="key">%s</div>'
        '<p style="font-size:13px">أو على الموبايل نفسه: <a href="%s">افتح في تطبيق التحقق</a></p>'
        % (e(grouped), e(uri)))
    return ('<!doctype html><html lang="ar" dir="rtl"><head><meta charset="utf-8">'
            '<meta name="viewport" content="width=device-width,initial-scale=1">'
            '<title>Sentinel | تجهيز الحساب</title><style>' + _AUTH_CSS + '</style></head><body>'
            '<div class="box"><h1>تجهيز حساب %s</h1>'
            '<p>خطوة مرة واحدة: كلمة مرور خاصة بك + التحقق بخطوتين.</p>' % e(username)
            + ('<p class="err" role="alert">%s</p>' % e(error) if error else "")
            + '<form method="post" action="/auth/setup"><input type="hidden" name="csrf" value="%s">' % e(csrf)
            + pw + steps +
            '<label for="code">اكتب الرمز الظاهر في التطبيق الآن</label>'
            '<input id="code" name="code" inputmode="numeric" autocomplete="one-time-code" required>'
            '<button>تفعيل والدخول</button></form></div></body></html>')


def _ts_short(value) -> str:
    try:
        if isinstance(value, (int, float)):
            return datetime.fromtimestamp(value, timezone.utc).strftime("%Y-%m-%d %H:%M")
        return str(value).replace("T", " ")[:16]
    except (ValueError, OSError):
        return "—"


AUTH_EVENT_AR = {
    "login_success": "دخول ناجح", "login_failed": "محاولة دخول فاشلة",
    "login_throttled": "حظر مؤقت لكثرة المحاولات", "logout": "خروج",
    "login_setup_started": "دخول أول (تجهيز)", "login_setup_completed": "فعّل التحقق بخطوتين",
    "user_create": "إنشاء مستخدم", "user_role": "تغيير دور", "user_disable": "تعطيل مستخدم",
    "user_enable": "تفعيل مستخدم", "user_reset_password": "إعادة تعيين كلمة مرور",
    "user_reset_mfa": "إعادة تعيين التحقق", "user_logout_all": "إنهاء الجلسات",
}


def users_admin(*, users, sessions, events, roles, me: str, notice: str = "",
                error: str = "", idle_minutes: int = 30) -> str:
    role_opts = lambda cur: "".join(  # noqa: E731
        '<option value="%s"%s>%s</option>' % (r, " selected" if r == cur else "",
                                             e(ROLE_AR.get(r, r))) for r in roles)
    rows = []
    for u in users:
        status = ("معطّل" if u.disabled else
                  "مقفول مؤقتًا" if u.locked_until and u.locked_until > datetime.now(timezone.utc).timestamp()
                  else "نشط")
        rows.append(
            '<tr><td><b>%s</b>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td class="actions">'
            '<form class="inline-form" hx-post="/users/action" hx-target="#view">'
            '<input type="hidden" name="op" value="role"><input type="hidden" name="username" value="%s">'
            '<select name="role">%s</select><button class="btn">حفظ الدور</button></form>'
            '<form class="inline-form" hx-post="/users/action" hx-target="#view" hx-confirm="تأكيد؟">'
            '<input type="hidden" name="op" value="%s"><input type="hidden" name="username" value="%s">'
            '<button class="btn %s">%s</button></form>'
            '<form class="inline-form" hx-post="/users/action" hx-target="#view" hx-confirm="إعادة تعيين التحقق بخطوتين؟">'
            '<input type="hidden" name="op" value="reset_mfa"><input type="hidden" name="username" value="%s">'
            '<button class="btn">إعادة التحقق</button></form>'
            '<form class="inline-form" hx-post="/users/action" hx-target="#view">'
            '<input type="hidden" name="op" value="reset_password"><input type="hidden" name="username" value="%s">'
            '<input type="password" name="password" placeholder="كلمة مرور مؤقتة" minlength="12" required>'
            '<button class="btn">تعيين مؤقتة</button></form></td></tr>'
            % (e(u.username), " (أنت)" if u.username == me else "",
               e(ROLE_AR.get(u.role, u.role)),
               "مفعّل" if u.mfa_enabled else "لم يُفعّل بعد", status,
               e(_ts_short(u.last_login)) if u.last_login else "لم يدخل بعد",
               e(u.username), role_opts(u.role),
               "enable" if u.disabled else "disable", e(u.username),
               "btn-ok" if u.disabled else "btn-no",
               "تفعيل" if u.disabled else "تعطيل", e(u.username), e(u.username)))
    sess_rows = "".join(
        '<tr><td>%s</td><td>%s</td><td><code>%s</code></td><td>%s</td></tr>'
        % (e(x["username"]), e(_ts_short(x["created"])), e(x["ip"] or "—"),
           e(_ts_short(x["last_seen"]))) for x in sessions) or \
        '<tr><td colspan="4" class="note">لا جلسات نشطة</td></tr>'
    ev_rows = "".join(
        '<tr><td>%s</td><td>%s</td><td><code>%s</code></td><td>%s</td><td class="note">%s</td></tr>'
        % (e(_ts_short(r[0])), e(AUTH_EVENT_AR.get(r[1], r[1])), e(r[2] or "—"),
           pill("healthy" if r[3] == "ok" else "down", "تم" if r[3] == "ok" else "رُفض"),
           e(r[4])) for r in events) or '<tr><td colspan="5" class="note">لا أحداث بعد</td></tr>'
    msg = ""
    if notice:
        msg = '<p class="pill pill-healthy" role="status">%s</p>' % e(notice)
    if error:
        msg = '<p class="warnbox" role="alert">%s</p>' % e(error)
    return (
        '<section class="card"><h2>المستخدمون والصلاحيات</h2>'
        '<p class="sub">مشاهد: يتفرّج فقط · محلل: يوافق ويرفض ويكتب ملاحظات ويتراجع عن إجراء · '
        'مدير: كل شيء بما فيه الإعدادات والحسابات. كل تغيير يُسجَّل باسمك.</p>' + msg +
        '<div class="tw"><table><thead><tr><th>المستخدم</th><th>الدور</th><th>التحقق بخطوتين</th>'
        '<th>الحالة</th><th>آخر دخول</th><th>إجراءات</th></tr></thead><tbody>%s</tbody></table></div>'
        '<h2 style="margin-top:22px">إضافة مستخدم</h2>'
        '<form class="inline-form" hx-post="/users/action" hx-target="#view">'
        '<input type="hidden" name="op" value="create">'
        '<label>اسم المستخدم<input name="username" required pattern="[a-z0-9._-]{3,32}"></label>'
        '<label>الدور<select name="role">%s</select></label>'
        '<label>كلمة مرور مؤقتة (12+)<input type="password" name="password" minlength="12" required></label>'
        '<button class="btn btn-go">إنشاء</button></form>'
        '<p class="note">المستخدم الجديد يدخل بكلمة المرور المؤقتة، ثم يختار كلمة مروره ويفعّل التحقق بخطوتين قبل أي شيء.</p>'
        '</section>'
        '<section class="card"><h2>الجلسات النشطة الآن</h2><p class="sub">تنتهي الجلسة تلقائيًا بعد %d دقيقة بدون نشاط.</p>'
        '<div class="tw"><table><thead><tr><th>المستخدم</th><th>بدأت</th><th>من عنوان</th><th>آخر نشاط</th></tr></thead>'
        '<tbody>%s</tbody></table></div></section>'
        '<section class="card"><h2>سجل الدخول والخروج</h2><p class="sub">من دخل، من فشل، من خرج، ومن غيّر الصلاحيات — من سجل التدقيق غير القابل للتعديل.</p>'
        '<div class="tw"><table><thead><tr><th>الوقت</th><th>الحدث</th><th>العنوان</th><th>النتيجة</th><th>التفاصيل</th></tr></thead>'
        '<tbody>%s</tbody></table></div></section>'
        % ("".join(rows), role_opts("viewer"), idle_minutes, sess_rows, ev_rows))



# -- inbox + incident story + printable report --------------------------------

def _hm(ts) -> str:
    text = str(ts or "")
    return text.replace("T", " ")[:19] if text else "—"


def _endpoint(ip, port) -> str:
    return "%s:%s" % (ip, port) if port else str(ip or "—")


def _evidence_split(ctx: Optional[dict]) -> tuple[list, list]:
    items = (ctx or {}).get("evidence") or []
    alerts = [x for x in items if isinstance(x, dict) and x.get("kind") == "alert"]
    flows = [x for x in items if isinstance(x, dict) and x.get("kind") == "flow"]
    return alerts, flows


def story_sentence(full: dict) -> str:
    ctx = full.get("context") or {}
    last = full["decisions"][-1] if full.get("decisions") else {}
    kind = ATTACK_AR.get(ctx.get("attack_type"), ctx.get("attack_type") or "نشاط مشبوه")
    who = []
    for d in full.get("decisions") or []:
        for ev in d.get("audit_events") or []:
            det = str(ev.get("detail", "")) if isinstance(ev, dict) else ""
            if " by " in det and "resolved" in det:
                who.append(det.rsplit(" by ", 1)[-1])
    decided = OUTCOME_AR.get(last.get("outcome"), last.get("outcome") or "—")
    return ("المصدر <code>%s</code> نفّذ <b>%s</b> ضد <code>%s</code> من %s إلى %s "
            "(%s تنبيه). قرار Sentinel: <b>%s</b>%s."
            % (e(ctx.get("src_ip")), e(kind), e(ctx.get("dst_ip")), e(_hm(ctx.get("first_ts"))),
               e(_hm(ctx.get("last_ts"))), e(ctx.get("alert_count", 0)), e(decided),
               (" · اعتمده/رفضه: %s" % e(", ".join(dict.fromkeys(who)))) if who else ""))


def incident_story(full: dict) -> str:
    alerts, flows = _evidence_split(full.get("context"))
    ev_rows = "".join(
        '<tr><td>%s</td><td>%s</td><td><code>%s</code></td><td><code>%s</code></td>'
        '<td>%s</td><td><span class="note"><code>%s</code></span></td></tr>'
        % (e(_hm(a.get("ts"))), e(a.get("what")), e(_endpoint(a.get("src"), a.get("sport"))),
           e(_endpoint(a.get("dst"), a.get("dport"))), e(a.get("proto")), e(a.get("ref")))
        for a in alerts) or '<tr><td colspan="6" class="note">لا توجد أدلة تفصيلية (حادثة أقدم من هذه النسخة).</td></tr>'
    conv: dict = {}
    for f in flows:
        src = (f.get("src") or "")
        peer = f.get("dst") if src == (full.get("context") or {}).get("src_ip") else src
        key = (peer, f.get("dport"), f.get("proto"))
        c = conv.setdefault(key, {"n": 0, "bytes": 0, "last": "", "what": ""})
        c["n"] += 1
        c["bytes"] += int(f.get("bytes") or 0)
        c["last"] = max(c["last"], str(f.get("ts") or ""))
        c["what"] = f.get("what") or c["what"]
    conv_rows = "".join(
        '<tr><td><code>%s</code></td><td>%s</td><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>'
        % (e(k[0]), e(k[1] or "—"), e(k[2]), e(v["n"]), e(v["bytes"] or "—"), e(v["what"] or "—"))
        for k, v in sorted(conv.items(), key=lambda kv: -kv[1]["n"])[:25]
    ) or '<tr><td colspan="6" class="note">لم تُسجَّل اتصالات أخرى لهذا المصدر في نافذة المراقبة.</td></tr>'
    return ('<div class="card"><h2>ماذا حدث</h2><p>%s</p></div>'
            '<div class="card"><h2>الأدلة بالترتيب الزمني</h2><p class="sub">ما رآه المستشعر بالضبط '
            '(بيانات وصفية فقط، لا محتوى حزم).</p><div class="tw"><table><thead><tr><th>الوقت</th>'
            '<th>ماذا</th><th>من</th><th>إلى</th><th>البروتوكول</th><th>المرجع</th></tr></thead>'
            '<tbody>%s</tbody></table></div></div>'
            '<div class="card"><h2>اتصالات المصدر</h2><p class="sub">مع من تكلّم هذا العنوان وعلى أي منفذ '
            '— آخر %d سجلًا رآها Sentinel.</p><div class="tw"><table><thead><tr><th>الطرف الآخر</th>'
            '<th>المنفذ</th><th>البروتوكول</th><th>عدد</th><th>بايت</th><th>تفاصيل</th></tr></thead>'
            '<tbody>%s</tbody></table></div></div>'
            % (story_sentence(full), ev_rows, len(flows), conv_rows))


def inbox(data: dict, pending: list, role: str = "admin") -> str:
    can_decide = role in ("analyst", "admin")
    cards = []
    for p in pending[:10]:
        aid = e(p["approval_id"])
        kind = e(ATTACK_AR.get(p.get("attack_type"), p.get("attack_type") or "—"))
        buttons = ""
        if can_decide:
            buttons = ('<button class="btn btn-ok" hx-post="/approvals/%s/approve" hx-target="#inbox-result" '
                       'hx-confirm="اعتماد الإجراء؟ سيُسجَّل باسمك.">اعتماد</button> '
                       '<button class="btn btn-no" hx-post="/approvals/%s/deny" hx-target="#inbox-result" '
                       'hx-confirm="رفض الإجراء؟">رفض</button>' % (aid, aid))
        cards.append(
            '<tr><td><b>%s</b><br><code>%s ← %s</code></td><td>%s</td><td><b>باقي %s</b></td>'
            '<td><a href="#" class="btn" hx-get="/ui/incident/%s" hx-target="#drawer">الدليل</a> %s</td></tr>'
            % (kind, e(p.get("dst_ip") or "—"), e(p.get("src_ip") or "—"),
               confidence_bar(p.get("confidence")), e(_countdown(p.get("deadline"))), aid, buttons))
    waiting = ('<div class="tw"><table><thead><tr><th>الهجوم</th><th>الثقة</th><th>المهلة</th><th></th></tr></thead>'
               '<tbody>%s</tbody></table></div>' % "".join(cards)) if cards else \
        '<p class="empty">لا شيء ينتظرك الآن. ✔</p>'
    rows = "".join(
        '<tr><td><code>%s</code></td><td>%s</td><td>%s</td><td><code>%s</code></td><td>%s</td>'
        '<td>%s</td><td>%s</td><td><a href="#" class="btn" hx-get="/ui/incident/%s" hx-target="#drawer">افتح</a></td></tr>'
        % (e(g["src_ip"]), e("، ".join(ATTACK_AR.get(t, t) for t in g["types"]) or "—"),
           outcome_pill(g["outcome"]), e(", ".join(g["targets"][:3]) + (" …" if len(g["targets"]) > 3 else "")),
           score_bar(g["max_score"]), e("%s حادثة · %s تنبيه" % (g["incidents"], g["alerts"])),
           e(_hm(g["last_seen"])), e(g["incident_id"]))
        for g in data["attackers"][:50])
    attacks = ('<div class="tw"><table><thead><tr><th>المصدر</th><th>النوع</th><th>القرار</th><th>الأهداف</th>'
               '<th>الخطورة</th><th>الحجم</th><th>آخر ظهور</th><th></th></tr></thead><tbody>%s</tbody></table></div>'
               % rows) if rows else '<p class="empty">لا هجمات تستحق الانتباه في آخر %d ساعة.</p>' % data["hours"]
    noise = "".join('<span class="chip">%s · %s</span>' % (e(ATTACK_AR.get(k, k)), e(n))
                    for k, n in data["noise_types"])
    return (
        '<div class="grid">'
        '<div class="kpi %s"><span>تنتظر قرارك</span><b>%d</b><small>موافقات مفتوحة</small></div>'
        '<div class="kpi %s"><span>مصادر هجوم</span><b>%d</b><small>آخر %d ساعة</small></div>'
        '<div class="kpi"><span>حوادث مهمة</span><b>%d</b><small>بعد استبعاد الضوضاء</small></div>'
        '<div class="kpi ok"><span>ضوضاء مخفية</span><b>%d</b><small>سُجّلت فقط</small></div></div>'
        '<div class="card"><h2>تنتظرك الآن</h2><p class="sub">كل قرار يُسجَّل باسمك في سجل التدقيق.</p>%s'
        '<div id="inbox-result" aria-live="polite"></div></div>'
        '<div class="card"><h2>الهجمات التي تستحق الانتباه</h2><p class="sub">مجمّعة حسب المهاجم، الأخطر أولًا. '
        'الإنذارات التي صنّفتها كاذبة أو سليمة لا تظهر هنا.</p>%s</div>'
        '<details class="card"><summary><b>الضوضاء المخفية (%d)</b> — أحداث منخفضة الخطورة سُجّلت ولم تُصعَّد</summary>'
        '<div class="chips" style="margin-top:10px">%s</div><p class="note">كلها موجودة في تبويب الحوادث والتدقيق.</p></details>'
        % ("bad" if pending else "ok", len(pending), "warn" if data["attackers"] else "ok",
           len(data["attackers"]), data["hours"], data["important_incidents"], data["noise_total"],
           waiting, attacks, data["noise_total"], noise or '<span class="note">لا شيء</span>'))


def incident_report(full: dict, *, generated_by: str, chain: Optional[dict]) -> str:
    """Standalone printable report (light theme; browser Print -> PDF)."""
    ctx = full.get("context") or {}
    last = full["decisions"][-1] if full.get("decisions") else {}
    body = incident_story(full) + score_explanation(full)
    trail = "".join(
        '<tr><td>%s</td><td>%s</td><td>%.0f%%</td><td>%s</td></tr>'
        % (e(_hm(d["ts"])), e(OUTCOME_AR.get(d["outcome"], d["outcome"])),
           float(d["score"]) * 100, e(d["would"])) for d in full.get("decisions") or [])
    notes = "".join('<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td></tr>'
                    % (e(_hm(n["ts"])), e(n["actor"]), e(LABEL_AR.get(n["label"], n["label"])), e(n["note"]))
                    for n in full.get("notes") or []) or '<tr><td colspan="4">لا ملاحظات</td></tr>'
    chain_txt = ("سليم ✔ (%s مدخل)" % chain.get("entries") if chain and chain.get("ok")
                 else "تحذير: فشل التحقق من السجل" if chain else "غير متاح")
    return (
        '<!doctype html><html lang="ar" dir="rtl"><head><meta charset="utf-8">'
        '<title>تقرير حادثة %s</title><style>'
        'body{font:14px/1.6 "Segoe UI",Tahoma,sans-serif;color:#111;background:#fff;margin:0}'
        'main{max-width:1000px;margin:auto;padding:24px}h1{font-size:22px;margin:0}'
        '.card{border:1px solid #ccd;border-radius:10px;padding:12px 14px;margin:12px 0;break-inside:avoid}'
        'table{width:100%%;border-collapse:collapse;font-size:12.5px}th,td{border-bottom:1px solid #dde;padding:5px;text-align:start;vertical-align:top}'
        'code{font-family:Consolas,monospace;direction:ltr;unicode-bidi:embed}.note,.sub{color:#555}'
        '.bar{display:inline-block;width:70px;height:7px;background:#dde;border-radius:9px;overflow:hidden}.bar i{display:block;height:100%%;background:#2a6fb0}'
        '.pill{border:1px solid #99a;border-radius:20px;padding:1px 8px;font-size:12px}'
        '.chips{display:flex;gap:4px;flex-wrap:wrap}.chip{border:1px solid #ccd;border-radius:6px;padding:0 6px}'
        '.meta{display:grid;grid-template-columns:repeat(2,1fr);gap:4px 16px;font-size:13px}'
        '@media print{.noprint{display:none}main{padding:0}}</style></head><body><main>'
        '<div style="display:flex;justify-content:space-between;align-items:center">'
        '<h1>Sentinel · تقرير حادثة</h1><button class="noprint" onclick="window.print()">طباعة / حفظ PDF</button></div>'
        '<div class="meta"><span>رقم الحادثة: <code>%s</code></span><span>المصدر: %s</span>'
        '<span>نوع الهجوم: %s</span><span>القرار الحالي: %s</span>'
        '<span>أُعدّ بواسطة: %s</span><span>وقت الإعداد: %s UTC</span>'
        '<span>سلامة سجل التدقيق: %s</span><span>الأصل: %s</span></div>'
        '%s<div class="card"><h2>مسار القرارات</h2><table><thead><tr><th>الوقت</th><th>القرار</th>'
        '<th>الدرجة</th><th>السبب</th></tr></thead><tbody>%s</tbody></table></div>'
        '<div class="card"><h2>مراجعات المحللين</h2><table><thead><tr><th>الوقت</th><th>المحلل</th>'
        '<th>التصنيف</th><th>الملاحظة</th></tr></thead><tbody>%s</tbody></table></div>'
        '<p class="note">هذا التقرير مبني على سجلات Sentinel غير القابلة للتعديل؛ الأدلة بيانات وصفية من '
        'Suricata/Zeek ولا تحتوي محتوى الحزم.</p></main></body></html>'
        % (e(full["incident_id"]), e(full["incident_id"]), e(ctx.get("src_ip")),
           e(ATTACK_AR.get(ctx.get("attack_type"), ctx.get("attack_type") or "—")),
           e(OUTCOME_AR.get(last.get("outcome"), last.get("outcome") or "—")), e(generated_by),
           e(datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M")), e(chain_txt),
           e(full.get("origin")), body, trail, notes))



AI_STATUS_AR = {"ok": "نجح", "parse_error": "رد غير صالح (تم تجاهله)",
                "transport_error": "تعذر الاتصال / انتهت المهلة"}


def ai_opinion(rows: list) -> str:
    if not rows:
        return ""
    r = rows[0]
    op = r.get("opinion")
    if not op:
        return ('<div class="card"><h2>رأي الذكاء الاصطناعي (استشاري)</h2>'
                '<p class="note">%s — القرار لم يتأثر.</p></div>'
                % e(AI_STATUS_AR.get(r["status"], r["status"])))
    return ('<div class="card"><h2>رأي الذكاء الاصطناعي (استشاري)</h2>'
            '<p>%s</p><p class="note">النوع المقترح: <b>%s</b> · ثقته %s · خطورة %s/5 · '
            'يقترح: %s · زمن الرد %s ms</p>'
            '<p class="note">استشاري فقط: لا يغيّر الدرجة ولا القرار ولا ينفّذ شيئًا. '
            'السؤال والإجابة محفوظان حرفيًا في سجل التدقيق.</p></div>'
            % (e(op["rationale"]), e(op["attack_type"]), confidence_bar(op["confidence"]),
               e(op["severity"]), e(op["action"]), e(r["elapsed_ms"])))


def ai_page(data: dict, status: dict) -> str:
    configured = status.get("configured")
    st = data["by_status"]
    total = sum(st.values())
    rows = "".join(
        '<tr><td>%s</td><td><a href="#" hx-get="/ui/incident/%s" hx-target="#drawer"><code>%s</code></a></td>'
        '<td>%s</td><td>%s</td><td>%s</td></tr>'
        % (e(str(r["ts"])[:19]), e(r["incident_id"]), e(short(r["incident_id"], 18)),
           pill("healthy" if r["status"] == "ok" else "down", AI_STATUS_AR.get(r["status"], r["status"])),
           e(r["elapsed_ms"]), e((r["opinion"] or {}).get("rationale", "—")))
        for r in data["recent"]) or '<tr><td colspan="5" class="note">لم يُستدعَ الموديل بعد.</td></tr>'
    return (
        '<div class="card"><h2>الذكاء الاصطناعي (AI agent)</h2>'
        '<p class="sub">رأي ثانٍ استشاري للحالات الغامضة. لا يملك أي صلاحية: لا يغيّر درجة ولا قرارًا ولا ينفّذ.</p>'
        '<div class="grid">'
        '<div class="kpi %s"><span>الحالة</span><b style="font-size:18px">%s</b><small>%s</small></div>'
        '<div class="kpi"><span>استدعاءات (%d س)</span><b>%d</b><small>ناجحة %d · فاشلة %d</small></div>'
        '<div class="kpi"><span>متوسط زمن الرد</span><b>%s</b><small>أقصى %s ms · الحد %s ث</small></div></div>'
        '<details style="margin-top:12px"><summary>كيف أتحكم فيه؟</summary><ul class="note">'
        '<li><b>التشغيل:</b> ضع رابط الموديل (متوافق مع OpenAI) في <code>SENTINEL_LLM_API</code> داخل <code>.env</code> ثم أعد التشغيل.</li>'
        '<li><b>الإيقاف الفوري:</b> امسح قيمة <code>SENTINEL_LLM_API</code> وأعد التشغيل؛ يكمل النظام بالقواعد وحدها.</li>'
        '<li><b>ما الذي يُرسل؟</b> حقول محددة فقط (نوع الإشارة، العناوين، المنافذ، العدد)؛ لا محتوى حزم ولا كلمات مرور.</li>'
        '<li><b>الحدود:</b> %s استدعاء/دقيقة كحد أقصى، مهلة قطع صارمة، وأي رد لا يطابق الصيغة يُرفض.</li>'
        '<li><b>المراجعة:</b> كل سؤال وإجابة محفوظان حرفيًا في سجل التدقيق غير القابل للتعديل.</li></ul></details></div>'
        '<div class="card"><h2>آخر الاستدعاءات</h2><div class="tw"><table><thead><tr><th>الوقت</th>'
        '<th>الحادثة</th><th>النتيجة</th><th>ms</th><th>رأيه</th></tr></thead><tbody>%s</tbody></table></div></div>'
        % ("ok" if configured else "warn", "متصل" if configured else "غير مفعّل",
           e(status.get("model") or ("الرابط في " + str(status.get("env")))) if configured
           else "اضبط SENTINEL_LLM_API لتفعيله",
           data["hours"], total, st.get("ok", 0), total - st.get("ok", 0),
           e(data["avg_ms"] if data["avg_ms"] is not None else "—"), e(data["max_ms"] or "—"),
           e(status.get("hard_cutoff_s", "—")), e(status.get("max_per_min", 6)), rows))
