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
  GET  /ui/*                      token   v2 dashboard fragments (read-only)
  POST /incidents/{id}/annotate   token   analyst label/note -> audit store ONLY
  GET  /static/htmx.min.js        NO AUTH — pure vendor file (DP2), zero
                                          operational data; named in
                                          DELIVERY-M7.md as THE exception.

Approve/deny enter the SAME validator chain as CLI: they call
``Engine.resolve(approval_id, approved)`` — the named seam — then persist
with the same record_decision call shape. No other write exists.
"""
from __future__ import annotations

import asyncio
import hmac
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from urllib.parse import parse_qs

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import (FileResponse, HTMLResponse, RedirectResponse,
                               Response, StreamingResponse)
from fastapi.staticfiles import StaticFiles

from sentinel.auditstore.store import Store
from sentinel.logging_setup import get_logger
from sentinel.ui.accounts import AccountStore, role_at_least
from sentinel.ui.auth import TOKEN_HEADER, TokenAuth
from sentinel.ui import analytics, pages, views

log = get_logger("sentinel.ui")

#: Session cookie (accounts mode): HttpOnly, SameSite=Strict, Secure on HTTPS.
SESSION_COOKIE = "sentinel_session"

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
               report_dir: Path | None = None,
               on_resolved=None, on_ack=None,
               critical_status=None, executor=None,
               config_path: Path | None = None) -> FastAPI:
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
    accounts: AccountStore | None = None
    auth: TokenAuth | None = None
    if ui_cfg.get("auth_mode", "token") == "accounts":
        db = ui_cfg.get("accounts_db") or str(
            Path((cfg.get("audit_store") or {}).get("path", "data/audit.sqlite"))
            .parent / "accounts.sqlite")
        accounts = AccountStore(db)
        if ui_cfg.get("allow_token_api") and os.environ.get(ui_cfg["auth_token_env"]):
            auth = TokenAuth(ui_cfg["auth_token_env"])
    else:
        auth = TokenAuth(ui_cfg["auth_token_env"])

    app = FastAPI(title="Sentinel Ops UI", docs_url=None, redoc_url=None,
                  openapi_url=None)
    app.state.engine = engine
    app.state.store = store
    app.state.capture_dir = capture_dir
    app.state.report_dir = Path(report_dir or "reports")
    app.state.port = port
    app.state.on_resolved = on_resolved
    app.state.on_ack = on_ack
    app.state.critical_status = critical_status
    app.state.executor = executor
    app.state.config_path = Path(config_path) if config_path else None
    app.state.accounts = accounts

    @app.middleware("http")
    async def _security_headers(request: Request, call_next):
        response = await call_next(request)
        h = response.headers
        h.setdefault("X-Frame-Options", "DENY")
        h.setdefault("X-Content-Type-Options", "nosniff")
        h.setdefault("Referrer-Policy", "no-referrer")
        h.setdefault("Content-Security-Policy",
                     "default-src 'self'; script-src 'self' 'unsafe-inline'; "
                     "style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
                     "frame-ancestors 'none'; form-action 'self'; base-uri 'none'")
        if not request.url.path.startswith("/static/"):
            h.setdefault("Cache-Control", "no-store")
        return response

    static_dir = Path(__file__).parent / "static"
    # DP2: mount ONLY the vendored file directory; every file in it must
    # appear in STATIC_EXCEPTION_FILES to keep the exception auditable.
    app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

    def _client_ip(request: Request) -> str:
        peer = request.client.host if request.client else ""
        # Only the local reverse proxy (Caddy on the same host) is trusted
        # to report the real client address.
        if peer in ("127.0.0.1", "::1"):
            fwd = request.headers.get("x-forwarded-for", "")
            if fwd:
                return fwd.split(",")[0].strip()[:64]
        return peer[:64]

    def _guard(request: Request, need: str = "viewer") -> str:
        """Authenticate + authorise; returns the acting user's name."""
        if accounts is None:
            auth.check(request)                       # legacy token mode
            request.state.actor = "ops_ui_authenticated"
            return request.state.actor
        if auth is not None and request.headers.get(TOKEN_HEADER):
            auth.check(request)                       # opt-in automation token
            request.state.actor = "api_token"
            return request.state.actor
        sess = accounts.session(request.cookies.get(SESSION_COOKIE))
        if sess is None or sess.stage != "full":
            raise HTTPException(status_code=401, detail="unauthorized")
        if request.method not in ("GET", "HEAD", "OPTIONS"):
            sent = request.headers.get("x-csrf-token", "")
            if not sent or not hmac.compare_digest(sent, sess.csrf):
                raise HTTPException(status_code=403, detail="csrf check failed")
        if not role_at_least(sess.role, need):
            raise HTTPException(status_code=403,
                                detail=f"this action needs the {need} role")
        request.state.actor = sess.username
        request.state.session = sess
        return sess.username

    def _actor(request: Request) -> str:
        return getattr(request.state, "actor", "ops_ui")

    def _audit_auth(event: str, user: str, request: Request, ok: bool,
                    detail: str = "") -> None:
        """Who logged in / out / failed: chained into the audit store."""
        if app.state.store is not None:
            app.state.store.record_action(
                case_id="auth", action_type=event, target_ip=_client_ip(request),
                ttl_minutes=None, verdict="ok" if ok else "refused",
                executed=False, detail=f"user={user} {detail}".strip()[:500])
        log.info("auth_event", auth_event=event, user=user, ok=ok)

    def _record_ui_change(action: str, detail: str, request: Request | None = None) -> None:
        if app.state.store is not None:
            by = _actor(request) if request is not None else "ops_ui"
            app.state.store.record_action(case_id="ops_ui", action_type=action,
                                          target_ip=None, ttl_minutes=None,
                                          verdict="saved", executed=False,
                                          detail=f"{detail} by={by}")

    # -- dashboard shell ------------------------------------------------ #
    @app.get("/login", response_class=HTMLResponse)
    def login() -> HTMLResponse:
        if accounts is not None:
            return HTMLResponse(pages.login_accounts(
                first_run=accounts.count() == 0))
        return HTMLResponse(pages.login(), headers={"Cache-Control": "no-store"})

    @app.get("/", response_class=HTMLResponse)
    def index(request: Request) -> Response:
        if accounts is not None:
            try:
                _guard(request)
            except HTTPException:
                return RedirectResponse("/login", status_code=303)
            sess = request.state.session
            return HTMLResponse(pages.shell(user={
                "name": sess.username, "role": sess.role, "csrf": sess.csrf}))
        _guard(request)
        return HTMLResponse(pages.shell())

    if accounts is not None:
        from sentinel.ui import account_routes
        account_routes.install(app, accounts=accounts, guard=_guard,
                               audit_auth=_audit_auth, client_ip=_client_ip,
                               cookie=SESSION_COOKIE)

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
                            request: Request, *, action_override: str | None = None,
                            ttl_minutes: int | None = None) -> Response:
        """THE approval write path — same seam as CLI (Engine.resolve)."""
        _guard(request, "analyst")
        if app.state.engine is None or app.state.store is None:
            raise HTTPException(status_code=409, detail=(
                "no engine/store attached; approvals unavailable in "
                "standalone observer mode"))
        try:
            decision = app.state.engine.resolve(approval_id, approved,
                                                actor=_actor(request),
                                                action_override=action_override,
                                                ttl_minutes=ttl_minutes)
        except KeyError as exc:
            raise HTTPException(status_code=404, detail=str(exc)) from None
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from None
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
                 approved=approved, actor=_actor(request))
        if app.state.on_resolved is not None:
            try:
                app.state.on_resolved(decision)      # executor (same seam)
            except Exception as exc:                 # never fail the approval
                log.warning("on_resolved_failed", error=type(exc).__name__)
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

    @app.post("/approvals/{approval_id}/modify")
    async def modify(approval_id: str, request: Request) -> Response:
        raw = (await request.body())[:8192].decode("utf-8", "replace")
        form = {k: v[0] for k, v in parse_qs(raw).items()}
        action = request.query_params.get("action") or form.get("action", "")
        try:
            ttl_minutes = int(request.query_params.get("ttl_minutes") or
                              form.get("ttl_minutes", "15"))
        except ValueError:
            raise HTTPException(status_code=422, detail="invalid ttl_minutes") from None
        return _resolve_and_record(approval_id, True, request,
                                   action_override=action,
                                   ttl_minutes=ttl_minutes)

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

    @app.get("/audit/export.json")
    def audit_export_json(request: Request, outcome: Optional[str] = None,
                          case_id: Optional[str] = None, q: Optional[str] = None) -> Response:
        _guard(request)
        rows = views.audit_search(_need_store(), outcome=outcome,
                                  case_id=case_id, q=q, limit=1000)
        return Response(views.serialize(rows), media_type="application/json",
                        headers={"Content-Disposition":
                                 "attachment; filename=sentinel-audit.json"})

    @app.get("/ui/events")
    async def ui_events(request: Request) -> StreamingResponse:
        _guard(request)
        async def stream():
            previous = None
            while not await request.is_disconnected():
                store = app.state.store
                head = store.chain_head().get("seq") if store else 0
                health = views.runtime_status(app.state.capture_dir)
                learning = health.get("learning") or {}
                current = (head, health.get("mode"), learning.get("observed_days"),
                           learning.get("extend_days"))
                if previous != current:
                    yield "data: %s\n\n" % json.dumps({"audit_seq": head, "mode": health.get("mode")})
                    previous = current
                await asyncio.sleep(2)
        return StreamingResponse(stream(), media_type="text/event-stream",
                                 headers={"Cache-Control": "no-cache",
                                          "X-Accel-Buffering": "no"})

    # -- Ops UI v2 pages (fragments; all token-guarded, read-only) --------- #
    def _page(html: str) -> HTMLResponse:
        return HTMLResponse(html)

    def _store_or_note() -> Optional[Store]:
        return app.state.store

    @app.get("/ui/mode", response_class=HTMLResponse)
    def ui_mode(request: Request) -> HTMLResponse:
        _guard(request)
        return _page(pages.mode_badge(views.runtime_status(app.state.capture_dir)))

    @app.get("/ui/overview", response_class=HTMLResponse)
    def ui_overview(request: Request, origin: str = "") -> HTMLResponse:
        _guard(request)
        store = _store_or_note()
        if store is None:
            return _page(pages.empty("لا يوجد سجل تدقيق مربوط بالواجهة."))
        ov = analytics.overview(store, origin=origin)
        level = int((cfg.get("autonomy_level", 0)) or 0)
        learning = views.runtime_status(app.state.capture_dir).get("learning") or {}
        return _page(pages.overview(
            ov, analytics.autonomy_readiness(ov, level,
                                             learning.get("observed_days")),
            views.kpis(store), len(views.pending_queue(app.state.engine)),
            analytics.incident_list(store, origin=origin)["rows"][:10], learning))

    @app.get("/ui/incidents", response_class=HTMLResponse)
    def ui_incidents(request: Request, outcome: str = "", tier: str = "",
                     attack_type: str = "", ip: str = "", q: str = "",
                     label: str = "", min_score: str = "",
                     origin: str = "", page: int = 1) -> HTMLResponse:
        _guard(request)
        store = _store_or_note()
        if store is None:
            return _page(pages.empty("لا يوجد سجل تدقيق مربوط بالواجهة."))
        try:
            ms = float(min_score) if min_score.strip() else None
        except ValueError:
            ms = None
        f = {"outcome": outcome, "tier": tier, "attack_type": attack_type,
             "ip": ip.strip(), "q": q.strip(), "label": label,
             "min_score": min_score.strip(), "origin": origin}
        listing = analytics.incident_list(
            store, outcome=outcome, tier=tier, attack_type=attack_type,
            ip=f["ip"], q=f["q"], label=label, min_score=ms,
            origin=origin, page=page)
        return _page(pages.incidents(listing, f))

    @app.get("/ui/ai", response_class=HTMLResponse)
    def ui_ai(request: Request) -> HTMLResponse:
        _guard(request)
        store = _store_or_note()
        if store is None:
            return _page(pages.empty("لا يوجد سجل تدقيق مربوط بالواجهة."))
        brain = cfg.get("brain") or {}
        env = brain.get("llm_endpoint_env", "SENTINEL_LLM_API")
        status = {"configured": bool(os.environ.get(env)), "env": env,
                  "model": brain.get("model"), "hard_cutoff_s": brain.get("hard_cutoff_s"),
                  "max_per_min": 6}
        return _page(pages.ai_page(analytics.ai_overview(store), status))

    @app.get("/ui/inbox", response_class=HTMLResponse)
    def ui_inbox(request: Request, hours: int = 24) -> HTMLResponse:
        _guard(request)
        store = _store_or_note()
        if store is None:
            return _page(pages.empty("لا يوجد سجل تدقيق مربوط بالواجهة."))
        pending = views.pending_queue(app.state.engine)
        for p in pending:
            row = store.query(
                "SELECT src_ip, dst_ip, attack_type FROM incident_context"
                " WHERE incident_id = ? ORDER BY id DESC LIMIT 1", (p["approval_id"],))
            if row:
                p["src_ip"], p["dst_ip"], p["attack_type"] = row[0]
        sess = getattr(request.state, "session", None)
        return _page(pages.inbox(analytics.inbox(store, hours=max(1, min(int(hours), 168))),
                                 pending, role=sess.role if sess else "admin"))

    @app.get("/incidents/{incident_id}/report", response_class=HTMLResponse)
    def incident_report(incident_id: str, request: Request) -> HTMLResponse:
        actor = _guard(request)
        store = _need_store()
        full = analytics.incident_full(store, incident_id)
        if full is None:
            raise HTTPException(status_code=404, detail="unknown incident")
        _record_ui_change("incident_report_viewed", incident_id, request)
        return HTMLResponse(pages.incident_report(full, generated_by=actor,
                                                  chain=store.verify_chain()))

    @app.get("/ui/incident/{incident_id}", response_class=HTMLResponse)
    def ui_incident(incident_id: str, request: Request) -> HTMLResponse:
        _guard(request)
        store = _store_or_note()
        if store is None:
            return _page(pages.empty("لا يوجد سجل تدقيق مربوط بالواجهة."))
        full = analytics.incident_full(store, incident_id)
        if full is None:
            return _page(pages.empty("لا توجد حادثة بهذا المعرّف."))
        return _page(pages.incident_detail(full, True))

    @app.post("/incidents/{incident_id}/annotate", response_class=HTMLResponse)
    async def annotate(incident_id: str, request: Request) -> HTMLResponse:
        """Analyst verdict/note — appended to the audit store ONLY. It never
        reaches the engine, so it cannot change or trigger any action."""
        _guard(request, "analyst")
        store = _store_or_note()
        if store is None:
            raise HTTPException(status_code=409, detail="no store attached")
        if analytics.incident_full(store, incident_id) is None:
            raise HTTPException(status_code=404, detail="unknown incident")
        raw = (await request.body())[:8192].decode("utf-8", "replace")
        form = {k: v[0] for k, v in parse_qs(raw).items()}
        label, note = form.get("label", ""), form.get("note", "").strip()
        if label not in ("",) + analytics.LABELS:
            raise HTTPException(status_code=422, detail="invalid label")
        if not label and not note:
            raise HTTPException(status_code=422, detail="empty annotation")
        store.record_analyst_note(incident_id=incident_id, actor=(_actor(request) if accounts is not None else "ops_ui"),
                                  label=label, note=note)
        log.info("analyst_annotation", incident_id=incident_id, label=label)
        return _page(pages.incident_detail(
            analytics.incident_full(store, incident_id), True))

    @app.post("/approvals/{approval_id}/ack", response_class=HTMLResponse)
    def ack_critical(approval_id: str, request: Request) -> HTMLResponse:
        """'I am handling it': stops the automatic deadline action for a
        critical case. Recorded by the escalation watch; changes no decision."""
        _guard(request, "analyst")
        if app.state.on_ack is None:
            raise HTTPException(status_code=409, detail=(
                "no escalation watch attached (run the live daemon with "
                "critical_response enabled)"))
        try:
            acked = app.state.on_ack(approval_id, _actor(request))
        except TypeError:                     # single-argument callbacks
            acked = app.state.on_ack(approval_id)
        if not acked:
            raise HTTPException(status_code=404, detail=(
                "no open critical case with that id, or already acknowledged"))
        log.info("critical_ack", approval_id=approval_id)
        return HTMLResponse('<p class="empty">تم تسجيل الاستلام: لن يتصرف النظام تلقائيًا في هذه الحالة.</p>')

    @app.get("/ui/approvals", response_class=HTMLResponse)
    def ui_approvals(request: Request) -> HTMLResponse:
        _guard(request)
        store = _store_or_note()
        pending = views.pending_queue(app.state.engine)
        history = []
        if store is not None:
            for p in pending:
                row = store.query(
                    "SELECT src_ip, dst_ip, attack_type, mitre FROM incident_context"
                    " WHERE incident_id = ? ORDER BY id DESC LIMIT 1",
                    (p["approval_id"],))
                if row:
                    p["src_ip"], p["dst_ip"], p["attack_type"], raw_mitre = row[0]
                    p["mitre"] = json.loads(raw_mitre)
            history = [dict(zip(("ts", "incident_id", "outcome", "case_id"), r))
                       for r in store.query(
                           "SELECT ts, incident_id, outcome, case_id FROM decisions"
                           " WHERE case_id IN ('ops_ui','telegram')"
                           " ORDER BY id DESC LIMIT 25")]
        cs = app.state.critical_status
        for p in pending:
            p["watch"] = cs(p["approval_id"]) if cs else None
        return _page(pages.approvals(pending, history,
                                     app.state.engine is not None,
                                     can_ack=app.state.on_ack is not None))

    @app.get("/ui/sources", response_class=HTMLResponse)
    def ui_sources(request: Request) -> HTMLResponse:
        _guard(request)
        return _page(pages.sources(views.capture_health(app.state.capture_dir)))

    @app.get("/ui/audit", response_class=HTMLResponse)
    def ui_audit(request: Request, outcome: str = "", case_id: str = "",
                 q: str = "") -> HTMLResponse:
        _guard(request)
        store = _store_or_note()
        if store is None:
            return _page(pages.empty("لا يوجد سجل تدقيق مربوط بالواجهة."))
        rows = views.audit_search(store, outcome=outcome or None,
                                  case_id=case_id or None, q=q or None,
                                  limit=100)
        return _page(pages.audit(rows, {"outcome": outcome,
                                        "case_id": case_id, "q": q}))

    @app.get("/ui/audit/verify", response_class=HTMLResponse)
    def ui_audit_verify(request: Request) -> HTMLResponse:
        _guard(request)
        store = _store_or_note()
        if store is None:
            return _page(pages.empty("لا يوجد سجل تدقيق مربوط بالواجهة."))
        return _page(pages.chain_report(store.verify_chain()))

    @app.get("/ui/settings", response_class=HTMLResponse)
    def ui_settings(request: Request) -> HTMLResponse:
        _guard(request)
        from sentinel.config.loader import load_config
        current = load_config(app.state.config_path) if app.state.config_path else cfg
        return _page(pages.settings(views.settings_view(
            current, app.state.capture_dir), editable=app.state.config_path is not None))

    def _write_ui_settings(updated: dict) -> None:
        import yaml
        from sentinel.config.loader import ui_override_path
        path = ui_override_path(updated)
        if path is None:
            raise HTTPException(status_code=409, detail="audit store path unavailable")
        changes = {"site": {"protected_ips": updated["site"].get("protected_ips", [])},
                   "policy": updated.get("policy") or {},
                   "limits": updated.get("limits") or {},
                   "notifiers": updated.get("notifiers") or [],
                   "enforcement_dry_run": updated.get("enforcement_dry_run", True)}
        path.parent.mkdir(parents=True, exist_ok=True)
        temp = path.with_suffix(".tmp")
        temp.write_text(yaml.safe_dump(changes, allow_unicode=True, sort_keys=False),
                        encoding="utf-8")
        temp.replace(path)

    @app.post("/settings/save", response_class=HTMLResponse)
    async def save_settings(request: Request) -> HTMLResponse:
        _guard(request, "admin")
        path = app.state.config_path
        if path is None:
            raise HTTPException(status_code=409, detail="configuration file not attached")
        import ipaddress
        from sentinel.config.loader import ConfigError, load_config, validate_config
        form = {k: v[0] for k, v in parse_qs(
            (await request.body())[:8192].decode("utf-8", "replace")).items()}
        try:
            updated = load_config(path)
            allowed = ("auto_act_threshold", "human_approval_threshold", "report_threshold")
            for name in allowed:
                updated.setdefault("policy", {})[name] = float(form[name])
            for name in ("approval_timeout_minutes", "report_timeout_minutes"):
                updated["policy"][name] = int(form[name])
            for name in ("max_blocks_per_min", "max_blocks_per_hour", "default_ttl_min"):
                updated.setdefault("limits", {})[name] = int(form[name])
            ips = [part.strip() for part in form["protected_ips"].split(",") if part.strip()]
            for address in ips:
                ipaddress.IPv4Address(address)
            updated["site"]["protected_ips"] = list(dict.fromkeys(ips))
            channels = json.loads(form["notifiers"])
            if not isinstance(channels, list):
                raise ValueError("notification channels must be a JSON list")
            updated["notifiers"] = channels
            validate_config(updated)
        except (KeyError, ValueError, ConfigError, json.JSONDecodeError) as exc:
            raise HTTPException(status_code=422, detail=f"invalid settings: {exc}") from None
        _write_ui_settings(updated)
        _record_ui_change("settings_saved", "restart_required", request)
        return _page(pages.settings(views.settings_view(updated, app.state.capture_dir),
                                    editable=True, saved=True))

    @app.post("/settings/dry-run", response_class=HTMLResponse)
    async def save_dry_run(request: Request) -> HTMLResponse:
        _guard(request, "admin")
        path = app.state.config_path
        if path is None:
            raise HTTPException(status_code=409, detail="configuration file not attached")
        from sentinel.config.loader import load_config, validate_config
        form = parse_qs((await request.body())[:1024].decode("utf-8", "replace"))
        value = (form.get("dry_run") or [""])[0]
        if value not in ("on", "off"):
            raise HTTPException(status_code=422, detail="invalid dry-run value")
        updated = load_config(path)
        if value == "off":
            runtime = views.runtime_status(app.state.capture_dir)
            if (updated.get("autonomy_level", 0) < 1 or
                    not updated["site"].get("protected_ips") or
                    runtime.get("mode") != "active" or
                    not runtime.get("fresh") or
                    any(s.get("status") != "healthy" for s in runtime.get("sources") or [])):
                raise HTTPException(status_code=409, detail="live enforcement safety gate not ready")
        updated["enforcement_dry_run"] = value == "on"
        validate_config(updated)
        _write_ui_settings(updated)
        _record_ui_change("dry_run_config_saved", value, request)
        return _page(pages.settings(views.settings_view(updated, app.state.capture_dir),
                                    editable=True, saved=True))

    def _learning():
        if app.state.store is None:
            raise HTTPException(status_code=409, detail="no learning profile attached")
        from sentinel.learning import LearningProfile
        path = app.state.store._path.with_name("learning.json")
        if not path.is_file():
            raise HTTPException(status_code=409, detail="learning profile unavailable")
        return LearningProfile(path)

    @app.get("/ui/learning", response_class=HTMLResponse)
    def ui_learning(request: Request) -> HTMLResponse:
        _guard(request)
        try:
            return _page(pages.learning(_learning().export()))
        except (ValueError, OSError) as exc:
            return _page(pages.empty(f"تعذر قراءة ملف التعلّم: {exc}"))

    @app.get("/learning/export.json")
    def learning_export(request: Request) -> Response:
        _guard(request)
        return Response(views.serialize(_learning().export()),
                        media_type="application/json",
                        headers={"Content-Disposition":
                                 "attachment; filename=sentinel-learning.json"})

    @app.post("/learning/mode", response_class=HTMLResponse)
    async def learning_mode(request: Request) -> HTMLResponse:
        _guard(request, "admin")
        form = parse_qs((await request.body())[:1024].decode("utf-8", "replace"))
        value = (form.get("mode") or [""])[0]
        if value not in ("auto", "learning", "active"):
            raise HTTPException(status_code=422, detail="invalid learning mode")
        profile = _learning()
        profile.set_override(value)
        _record_ui_change("learning_mode_override", value, request)
        return _page(pages.learning(profile.export()))

    @app.post("/learning/extend", response_class=HTMLResponse)
    async def learning_extend(request: Request) -> HTMLResponse:
        _guard(request, "admin")
        form = parse_qs((await request.body())[:1024].decode("utf-8", "replace"))
        try:
            days = int((form.get("days") or [""])[0])
            profile = _learning()
            profile.extend(days)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from None
        _record_ui_change("learning_extend_days", str(days), request)
        return _page(pages.learning(profile.export()))

    def _intel_data(q: str = "") -> dict:
        from sentinel.threatintel.attack import load_attack_catalog
        store = app.state.store
        base = store._path.parent if store else Path("data")
        path = base / "attack-catalog.json"
        catalog = load_attack_catalog(path)
        terms = q.strip().lower()[:80]
        techniques = [v for k, v in catalog.get("techniques", {}).items()
                      if not terms or terms in k.lower() or
                      terms in str(v.get("name", "")).lower()][:100]
        cve_path = base / "cve-cache.json"
        try:
            cve = json.loads(cve_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            cve = {}
        return {"q": q, "source": catalog.get("source"),
                "techniques": techniques,
                "technique_count": len(catalog.get("techniques", {})),
                "refreshed_at": datetime.fromtimestamp(path.stat().st_mtime, timezone.utc).isoformat()
                if path.is_file() else None,
                "cve_count": len(cve.get("entries", cve)) if isinstance(cve, dict) else 0,
                "cves": [k for k in cve if terms in k.lower()][:100] if isinstance(cve, dict) else []}

    @app.get("/ui/intel", response_class=HTMLResponse)
    def ui_intel(request: Request, q: str = "") -> HTMLResponse:
        _guard(request)
        return _page(pages.intel(_intel_data(q)))

    @app.get("/ui/actions", response_class=HTMLResponse)
    def ui_actions(request: Request) -> HTMLResponse:
        _guard(request)
        store = _need_store()
        actions = store.query("SELECT id, ts, case_id, action_type, target_ip, ttl_minutes,"
                              " verdict, executed, detail FROM actions WHERE case_id != 'auth'"
                              " ORDER BY id DESC LIMIT 100")
        rollbacks = store.query("SELECT ts, case_id, ok, detail FROM rollbacks"
                                " ORDER BY id DESC LIMIT 30")
        active = app.state.executor.active() if app.state.executor else []
        return _page(pages.actions(actions, rollbacks, active,
                                   app.state.executor is not None))

    @app.post("/actions/rollback", response_class=HTMLResponse)
    async def ui_rollback(request: Request) -> HTMLResponse:
        _guard(request, "analyst")
        if app.state.executor is None:
            raise HTTPException(status_code=409, detail="no executor attached")
        form = parse_qs((await request.body())[:2048].decode("utf-8", "replace"))
        action = (form.get("action") or [""])[0]
        target = (form.get("target") or [""])[0]
        if not app.state.executor.rollback_one(action, target):
            raise HTTPException(status_code=404, detail="active action not found or rollback failed")
        return ui_actions(request)

    def _report() -> dict:
        store = _need_store()
        first = analytics.incident_list(store, page=1)
        items = list(first["rows"])
        for page in range(2, first["pages"] + 1):
            items.extend(analytics.incident_list(store, page=page)["rows"])
        return {"generated_at": datetime.now(timezone.utc).isoformat(),
                "runtime": views.runtime_status(app.state.capture_dir),
                "kpis": views.kpis(store), "audit_chain": store.verify_chain(),
                "incidents": items,
                "actions": [dict(zip(("ts", "action", "target", "verdict", "executed"), r))
                            for r in store.query("SELECT ts, action_type, target_ip, verdict, executed"
                                                 " FROM actions ORDER BY id DESC")]}

    @app.get("/ui/reports", response_class=HTMLResponse)
    def ui_reports(request: Request) -> HTMLResponse:
        _guard(request)
        path = app.state.report_dir / "latest.json"
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            data = None
        return _page(pages.reports(data))

    @app.post("/reports/generate", response_class=HTMLResponse)
    def generate_report(request: Request) -> HTMLResponse:
        _guard(request, "analyst")
        report = _report()
        path = app.state.report_dir / "latest.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        temp = path.with_suffix(".tmp")
        temp.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
        temp.replace(path)
        return _page(pages.reports(report))

    @app.get("/reports/latest.json")
    def latest_json(request: Request) -> Response:
        _guard(request)
        path = app.state.report_dir / "latest.json"
        if not path.is_file():
            raise HTTPException(status_code=404, detail="no report generated")
        return FileResponse(path, media_type="application/json",
                            filename="sentinel-report.json")

    @app.get("/ui/guide", response_class=HTMLResponse)
    def ui_guide(request: Request) -> HTMLResponse:
        _guard(request)
        return _page(pages.guide())

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
          report_dir: Path | None = None,
          on_resolved=None, on_ack=None,
          critical_status=None, executor=None,
          config_path: Path | None = None) -> None:
    """Blocking uvicorn run bound to the validated loopback host:port."""
    import uvicorn
    ui_cfg = cfg["ops_ui"]
    host = ui_cfg["bind"].rsplit(":", 1)[0].strip("[]")
    app = create_app(cfg, engine=engine, store=store, capture_dir=capture_dir,
                     report_dir=report_dir, on_resolved=on_resolved,
                     on_ack=on_ack, critical_status=critical_status,
                     executor=executor, config_path=config_path)
    uvicorn.run(app, host=host, port=app.state.port, log_level="warning")
