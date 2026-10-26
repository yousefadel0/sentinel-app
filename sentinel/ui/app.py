"""FastAPI application factory for the Minimal Ops UI (M7).

Route/auth matrix (P6 — single declared exception):
  GET  /                          token   dashboard shell (htmx)
  GET  /health/capture            token   capture health (read-only)
  GET  /approvals                 token   pending approvals queue
  POST /approvals/{id}/approve    token   → Engine.resolve(id, True)
  POST /approvals/{id}/deny       token   → Engine.resolve(id, False)
  GET  /incidents/recent          token   recent decisions viewer
  GET  /kpis                      token   KPI counters (exact names, P5)
  GET  /incidents/{id}            token   incident decision history (read-only)
  GET  /audit/search              token   filtered decisions (read-only)
  GET  /audit/export.csv          token   CSV export (read-only)
  GET  /static/htmx.min.js        NO AUTH — pure vendor file (DP2), zero
                                          operational data; named in
                                          DELIVERY-M7.md as THE exception.

Approve/deny enter the SAME validator chain as CLI: they call
``Engine.resolve(approval_id, approved)`` — the named seam — then persist
with the same record_decision call shape. No other write exists.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, HTMLResponse, Response
from fastapi.staticfiles import StaticFiles

from sentinel.auditstore.store import Store
from sentinel.logging_setup import get_logger
from sentinel.ui.auth import TokenAuth
from sentinel.ui import views

log = get_logger("sentinel.ui")

#: DP2 auditability: the ONLY unauthenticated route serves exactly this
#: vendored asset (pure htmx library file, zero operational data).
STATIC_EXCEPTION_FILES = ("htmx.min.js",)

_SHELL = """<!doctype html>
<html lang="ar" dir="rtl"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Sentinel | لوحة المراقبة</title>
<script src="/static/htmx.min.js"></script>
<style>
:root{color-scheme:dark;--bg:#0b1220;--panel:#111c2e;--panel2:#16243a;--line:#24344d;--text:#e7eef9;--muted:#9aabc3;--blue:#61a9ff;--green:#42d392;--amber:#f4bd58;--red:#ff7385}
*{box-sizing:border-box}body{margin:0;background:radial-gradient(ellipse at 80% -10%,#183252 0,transparent 40%),var(--bg);color:var(--text);font:15px/1.65 "Segoe UI",Tahoma,Arial,sans-serif}
.wrap{max-width:1440px;margin:auto;padding:28px clamp(16px,3vw,42px) 50px}.topbar{display:flex;align-items:center;justify-content:space-between;gap:18px;padding-bottom:22px;border-bottom:1px solid var(--line)}
.brand{display:flex;align-items:center;gap:12px;font-size:20px;font-weight:750;letter-spacing:.2px}.brand-mark{display:grid;place-items:center;width:42px;height:42px;border-radius:13px;background:linear-gradient(145deg,#2775ce,#174283);color:white;font-size:22px}.brand small{display:block;color:var(--muted);font-size:12px;font-weight:500;letter-spacing:0}
.pill{display:inline-flex;align-items:center;gap:8px;border:1px solid #24533f;border-radius:999px;padding:7px 12px;background:#10271f;color:#a8f0cc;font-size:12px}.dot{width:8px;height:8px;border-radius:50%;background:var(--green);box-shadow:0 0 12px #42d39280}
.hero{padding:28px 0 22px}.eyebrow{color:var(--blue);font-size:12px;font-weight:700;letter-spacing:1px}.hero h1{margin:4px 0;font-size:clamp(25px,4vw,34px);line-height:1.3}.hero p{margin:7px 0 0;color:var(--muted);max-width:850px}
.notice{display:flex;align-items:flex-start;gap:12px;padding:13px 16px;margin:0 0 20px;border:1px solid #554625;background:#2b2415;color:#f5d99a;border-radius:12px}.notice strong{display:block;color:#ffe7ae}.notice span{font-size:13px}
.section{margin-top:20px;padding:20px;background:linear-gradient(160deg,#121e30,#101a2a);border:1px solid var(--line);border-radius:16px;box-shadow:0 10px 35px #00000018}.section-head{display:flex;justify-content:space-between;align-items:flex-start;gap:14px;margin-bottom:16px}.section h2{font-size:18px;margin:0}.section-head p{margin:3px 0 0;color:var(--muted);font-size:13px}.refresh{color:#8da5c6;font-size:12px;white-space:nowrap}
.metrics-grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px}.metric{min-height:126px;padding:16px;border:1px solid var(--line);border-radius:12px;background:var(--panel2);display:flex;flex-direction:column;gap:4px}.metric>span{color:#b4c3d9;font-size:12px}.metric strong{font-size:25px;line-height:1.35;color:#f2f7ff;overflow-wrap:anywhere}.metric small{color:var(--muted);font-size:11px}.metric-safe strong{color:var(--green)}.subtle{color:var(--muted);font-size:12px;margin:14px 2px 0}
.source-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:10px}.source-card{display:flex;flex-direction:column;gap:7px;padding:14px;border:1px solid var(--line);border-radius:11px;background:#0e1929}.source-card strong{font-family:Consolas,monospace;direction:ltr;text-align:right;overflow-wrap:anywhere}.source-card>span:not(.status){font-size:12px;color:var(--muted)}.status,.outcome{display:inline-flex;width:max-content;border-radius:999px;padding:3px 9px;font-size:11px;font-weight:700;background:#25334a;color:#d5e1f3}.status-healthy,.outcome-auto_act,.outcome-auto_throttle{background:#123a2c;color:#a8f0cc}.status-degraded,.outcome-human_approval,.outcome-escalate_human{background:#493717;color:#ffe0a0}.status-down{background:#40232c;color:#ffb5c0}
.table-wrap{overflow:auto;border:1px solid var(--line);border-radius:10px}table{width:100%;border-collapse:collapse;min-width:760px;text-align:right}th{font-size:12px;font-weight:650;color:#a9bad2;background:#17253a}td,th{padding:11px 12px;border-bottom:1px solid #223149;vertical-align:top}tbody tr:last-child td{border-bottom:0}tbody tr:hover{background:#19283d}td{font-size:13px}code{font:12px Consolas,monospace;color:#a9d0ff;direction:ltr;unicode-bidi:embed}.reason{min-width:300px;color:#c0cde0}.score{display:inline-block;vertical-align:middle;width:54px;height:6px;border-radius:6px;background:#2a3950;overflow:hidden;margin-left:5px}.score span{display:block;height:100%;background:var(--blue);border-radius:6px}.empty-state{padding:14px 16px;border:1px dashed #344760;border-radius:10px;color:#b5c5da;background:#0e1929;margin:0}
.button{border:0;border-radius:7px;padding:7px 11px;color:#08111d;font-weight:700;cursor:pointer}.button-approve{background:#67dda8}.button-deny{background:#ff8795}.actions{white-space:nowrap}.footer{display:flex;justify-content:space-between;gap:16px;color:#8093ad;font-size:11px;padding:22px 4px}.htmx-request{opacity:.55;transition:opacity .15s}
@media(max-width:900px){.metrics-grid{grid-template-columns:repeat(2,minmax(0,1fr))}.section{padding:15px}.hero{padding-top:22px}}
@media(max-width:540px){.wrap{padding:16px 12px 32px}.topbar{align-items:flex-start;flex-direction:column}.metrics-grid{grid-template-columns:1fr 1fr;gap:8px}.metric{padding:12px;min-height:112px}.metric strong{font-size:21px}.section-head{flex-direction:column}.refresh{white-space:normal}}
</style></head>
<body><div class="wrap">
<header class="topbar"><div class="brand"><span class="brand-mark">S</span><span>Sentinel<small>مركز مراقبة القرارات الأمنية</small></span></div><span class="pill"><i class="dot"></i> الخدمة تعمل · محلية وآمنة</span></header>
<div class="hero"><span class="eyebrow">لوحة التشغيل</span><h1>ملخص حالة Sentinel</h1><p>تابع ملفات الأحداث التجريبية، قرارات التحليل، ومؤشرات التشغيل من مكان واحد.</p></div>
<aside class="notice"><span>ⓘ</span><span><strong>وضع تجريبي — Shadow Pilot</strong>البيانات هنا ناتجة عن إعادة تشغيل ملفات. لا يوجد التقاط مباشر للشبكة، ولا يتم تنفيذ إجراءات دفاعية في هذا التشغيل.</span></aside>
<main>
<section class="section"><div class="section-head"><div><h2>المؤشرات الرئيسية</h2><p>ملخص الأرقام المسجلة في قاعدة التدقيق</p></div><span class="refresh">تحديث تلقائي كل 30 ثانية</span></div><div id="kpis" hx-get="/dashboard/kpis" hx-trigger="load, every 30s">جارٍ تحميل المؤشرات…</div></section>
<section class="section"><div class="section-head"><div><h2>مصادر الأحداث</h2><p>حالة ملفات replay الموجودة في مجلد capture</p></div><span class="refresh">تحديث تلقائي كل 10 ثوانٍ</span></div><div id="capture" class="source-grid" hx-get="/dashboard/health" hx-trigger="load, every 10s">جارٍ فحص الملفات…</div></section>
<section class="section"><div class="section-head"><div><h2>الموافقات البشرية</h2><p>القرارات التي تحتاج مراجعة بشرية قبل اعتمادها</p></div><span class="refresh">تحديث تلقائي كل 5 ثوانٍ</span></div><div id="approvals" hx-get="/dashboard/approvals" hx-trigger="load, every 5s">جارٍ تحميل قائمة الموافقات…</div></section>
<section class="section"><div class="section-head"><div><h2>تقرير آخر تشغيل</h2><p>تقرير مفصل للهجمات والأدلة وقرارات Sentinel وسياق ATT&CK</p></div></div><div id="report-link" hx-get="/dashboard/report" hx-trigger="load, every 30s">جارٍ البحث عن تقرير…</div></section>
<section class="section"><div class="section-head"><div><h2>أحدث الحوادث والقرارات</h2><p>آخر 20 قرارًا، مع الدرجة وسبب القرار</p></div><span class="refresh">تحديث تلقائي كل 15 ثانية</span></div><div id="incidents" hx-get="/dashboard/incidents" hx-trigger="load, every 15s">جارٍ تحميل الحوادث…</div></section>
<section class="section"><div class="section-head"><div><h2>تفاصيل الحادثة</h2><p>اختر حادثة من الجدول أعلاه</p></div></div><div id="incident-detail" class="empty-state">لم تُختر حادثة بعد.</div></section>
</main><footer class="footer"><span>Sentinel · لوحة محلية للقراءة والمراجعة</span><span>السجل تراكمي؛ إعادة تشغيل الـPilot تضيف نتائج جديدة</span></footer></div></body></html>"""


def create_app(cfg: dict, engine=None, store: Store | None = None,
               capture_dir: Path | None = None,
               report_dir: Path | None = None) -> FastAPI:
    """Build the ops UI app from a VALIDATED config.

    Fail-closed rules enforced here at construction time:
      * ops_ui.enabled must be true to serve at all (default stays false);
      * bind re-validated via bindcheck (loopback invariant + allowlist);
      * token env var must be set (auth.TokenAuth raises otherwise).
    """
    from sentinel.ui.bindcheck import validate_bind

    ui_cfg = cfg.get("ops_ui", {})
    if not ui_cfg.get("enabled"):
        raise RuntimeError(
            "ops_ui.enabled is false; refusing to start the Ops UI "
            "(never on by default — explicit operator opt-in required)")
    port = validate_bind(ui_cfg["bind"], ui_cfg.get("allowed_ports"))
    auth = TokenAuth(ui_cfg["auth_token_env"])

    app = FastAPI(title="Sentinel Ops UI", docs_url=None, redoc_url=None,
                  openapi_url=None)
    app.state.engine = engine
    app.state.store = store
    app.state.capture_dir = capture_dir
    app.state.report_dir = Path(report_dir or "reports")
    app.state.port = port

    static_dir = Path(__file__).parent / "static"
    # DP2: mount ONLY the vendored file directory; every file in it must
    # appear in STATIC_EXCEPTION_FILES to keep the exception auditable.
    app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

    def _guard(request: Request) -> None:
        auth.check(request)

    # -- dashboard shell ------------------------------------------------ #
    @app.get("/", response_class=HTMLResponse)
    def index(request: Request) -> HTMLResponse:
        _guard(request)
        return HTMLResponse(_SHELL)

    # Human-readable fragments are separate from the stable JSON API below.
    @app.get("/dashboard/health", response_class=HTMLResponse)
    def dashboard_health(request: Request) -> HTMLResponse:
        _guard(request)
        return HTMLResponse(views.render_capture(app.state.capture_dir))

    @app.get("/dashboard/approvals", response_class=HTMLResponse)
    def dashboard_approvals(request: Request) -> HTMLResponse:
        _guard(request)
        return HTMLResponse(views.render_approvals(app.state.engine))

    @app.get("/dashboard/incidents", response_class=HTMLResponse)
    def dashboard_incidents(request: Request) -> HTMLResponse:
        _guard(request)
        return HTMLResponse(views.render_incidents(app.state.store))

    @app.get("/dashboard/kpis", response_class=HTMLResponse)
    def dashboard_kpis(request: Request) -> HTMLResponse:
        _guard(request)
        return HTMLResponse(views.render_kpis(app.state.store))

    @app.get("/dashboard/report", response_class=HTMLResponse)
    def dashboard_report(request: Request) -> HTMLResponse:
        _guard(request)
        return HTMLResponse(views.render_report_link(app.state.report_dir))

    @app.get("/reports/latest", response_class=HTMLResponse)
    def latest_report(request: Request) -> Response:
        _guard(request)
        path = app.state.report_dir / "latest.html"
        if not path.is_file():
            raise HTTPException(status_code=404, detail="no report has been generated yet")
        return FileResponse(
            path, media_type="text/html; charset=utf-8",
            headers={"Content-Disposition": "inline; filename=sentinel-latest-report.html"},
        )

    # -- capture health (read-only) ------------------------------------- #
    @app.get("/health/capture")
    def health_capture(request: Request) -> Response:
        _guard(request)
        return Response(
            views.serialize(views.capture_health(app.state.capture_dir)),
            media_type="application/json")

    # -- approvals queue + THE approval flow ---------------------------- #
    @app.get("/approvals")
    def approvals(request: Request) -> Response:
        _guard(request)
        return Response(
            views.serialize(views.pending_queue(app.state.engine)),
            media_type="application/json")

    def _resolve_and_record(approval_id: str, approved: bool,
                            request: Request) -> Response:
        """THE approval write path — same seam as CLI (Engine.resolve)."""
        _guard(request)
        if app.state.engine is None or app.state.store is None:
            raise HTTPException(status_code=409, detail=(
                "no engine/store attached; approvals unavailable in "
                "standalone observer mode"))
        try:
            decision = app.state.engine.resolve(approval_id, approved)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from None
        rec = decision.recommendation
        app.state.store.record_decision(
            case_id="ops_ui",
            incident_id=decision.incident_id,
            outcome=decision.outcome.value,
            score=float(decision.score),
            base_score=float(decision.base_score),
            tier=decision.tier,
            cap_applied=decision.cap_applied,
            would=decision.would,
            recommendation=(json.loads(json.dumps(rec.__dict__, default=str))
                            if rec is not None else {}),
            audit_events=[{"name": e.name, "detail": e.detail}
                          for e in decision.audit_events],  # P6 complete path
        )
        log.info("approval_resolved", approval_id=approval_id,
                 approved=approved)
        if request.headers.get("HX-Request", "").lower() == "true":
            status = "اعتماد" if approved else "رفض"
            return HTMLResponse(f'<p class="empty-state">تم تسجيل {status} القرار.</p>')
        return Response(views.serialize({
            "approval_id": approval_id,
            "resolved_outcome": decision.outcome.value,
        }), media_type="application/json")

    @app.post("/approvals/{approval_id}/approve")
    def approve(approval_id: str, request: Request) -> Response:
        return _resolve_and_record(approval_id, True, request)

    @app.post("/approvals/{approval_id}/deny")
    def deny(approval_id: str, request: Request) -> Response:
        return _resolve_and_record(approval_id, False, request)

    # -- incidents viewer (read-only) ----------------------------------- #
    @app.get("/incidents/recent")
    def incidents(request: Request) -> Response:
        _guard(request)
        if app.state.store is None:
            raise HTTPException(status_code=409, detail="no store attached")
        return Response(
            views.serialize(views.recent_incidents(app.state.store)),
            media_type="application/json")

    # -- Phase 2: incident detail / audit search / export (read-only) ----- #
    def _need_store() -> Store:
        if app.state.store is None:
            raise HTTPException(status_code=409, detail="no store attached")
        return app.state.store

    @app.get("/incidents/{incident_id}")
    def incident_json(incident_id: str, request: Request) -> Response:
        _guard(request)
        detail = views.incident_detail(_need_store(), incident_id)
        if detail is None:
            raise HTTPException(status_code=404, detail="unknown incident")
        return Response(views.serialize(detail), media_type="application/json")

    @app.get("/dashboard/incident/{incident_id}", response_class=HTMLResponse)
    def dashboard_incident(incident_id: str, request: Request) -> HTMLResponse:
        _guard(request)
        return HTMLResponse(
            views.render_incident_detail(app.state.store, incident_id))

    @app.get("/audit/search")
    def audit_search(request: Request, outcome: Optional[str] = None,
                     case_id: Optional[str] = None, tier: Optional[str] = None,
                     q: Optional[str] = None, min_score: Optional[float] = None,
                     limit: int = 100, offset: int = 0) -> Response:
        _guard(request)
        rows = views.audit_search(_need_store(), outcome=outcome,
                                  case_id=case_id, tier=tier, q=q,
                                  min_score=min_score, limit=limit,
                                  offset=offset)
        return Response(views.serialize(rows), media_type="application/json")

    @app.get("/audit/export.csv")
    def audit_export(request: Request, outcome: Optional[str] = None,
                     case_id: Optional[str] = None, tier: Optional[str] = None,
                     q: Optional[str] = None, min_score: Optional[float] = None,
                     limit: int = 1000) -> Response:
        _guard(request)
        rows = views.audit_search(_need_store(), outcome=outcome,
                                  case_id=case_id, tier=tier, q=q,
                                  min_score=min_score, limit=limit)
        return Response(views.audit_csv(rows), media_type="text/csv",
                        headers={"Content-Disposition":
                                 "attachment; filename=sentinel-audit.csv"})

    # -- KPI counters (read-only; exact names per P5) -------------------- #
    @app.get("/kpis")
    def kpis(request: Request) -> Response:
        _guard(request)
        if app.state.store is None:
            raise HTTPException(status_code=409, detail="no store attached")
        return Response(
            views.serialize(views.kpis(app.state.store)),
            media_type="application/json")

    return app


def serve(cfg: dict, engine=None, store: Store | None = None,
          capture_dir: Path | None = None,
          report_dir: Path | None = None) -> None:
    """Blocking uvicorn run bound to the validated loopback host:port."""
    import uvicorn
    ui_cfg = cfg["ops_ui"]
    host = ui_cfg["bind"].rsplit(":", 1)[0].strip("[]")
    app = create_app(cfg, engine=engine, store=store, capture_dir=capture_dir,
                     report_dir=report_dir)
    uvicorn.run(app, host=host, port=app.state.port, log_level="warning")
