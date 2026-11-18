"""Login / first-login setup / logout / user administration (accounts mode).

Flow:
  1. ``POST /auth/login`` username + password (+ 6-digit code once MFA is on).
  2. First login (or after an admin password reset) -> a short-lived *setup*
     session -> ``/auth/setup``: choose a new password and enrol the
     authenticator app by typing one valid code. Only then a full session.
  3. ``POST /auth/logout`` revokes the session server-side.

Every attempt (ok or refused) is written to the audit store by
``audit_auth`` with the client address, so "who logged in, who failed, who
logged out" is a tamper-evident record, not a web-server log.
"""
from __future__ import annotations

import hmac
import time
from collections import defaultdict, deque
from urllib.parse import parse_qs

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response

from sentinel.ui import pages
from sentinel.ui.accounts import (ROLES, AccountError, AccountStore, IDLE_SECONDS,
                                  otpauth_uri)

#: Per-client-address brake on top of the per-account lockout.
IP_WINDOW_S = 15 * 60
IP_MAX_FAILURES = 20


def install(app: FastAPI, *, accounts: AccountStore, guard, audit_auth,
            client_ip, cookie: str) -> None:
    failures: dict[str, deque] = defaultdict(deque)

    def _ip_blocked(ip: str) -> bool:
        q = failures[ip]
        now = time.time()
        while q and now - q[0] > IP_WINDOW_S:
            q.popleft()
        return len(q) >= IP_MAX_FAILURES

    def _secure(request: Request) -> bool:
        if request.url.scheme == "https":
            return True
        peer = request.client.host if request.client else ""
        return peer in ("127.0.0.1", "::1") and \
            request.headers.get("x-forwarded-proto", "") == "https"

    def _set_cookie(resp: Response, request: Request, sid: str) -> None:
        resp.set_cookie(cookie, sid, httponly=True, samesite="strict",
                        secure=_secure(request), path="/",
                        max_age=12 * 3600)

    async def _form(request: Request, limit: int = 4096) -> dict:
        raw = (await request.body())[:limit].decode("utf-8", "replace")
        return {k: v[0] for k, v in parse_qs(raw, keep_blank_values=True).items()}

    def _login_page(error: str = "", status: int = 200, need_code: bool = False,
                    username: str = "") -> HTMLResponse:
        return HTMLResponse(pages.login_accounts(error=error, need_code=need_code,
                                                 username=username,
                                                 first_run=accounts.count() == 0),
                            status_code=status)

    # -- login -----------------------------------------------------------------
    @app.post("/auth/login", response_class=HTMLResponse)
    async def auth_login(request: Request) -> Response:
        ip = client_ip(request)
        if _ip_blocked(ip):
            audit_auth("login_throttled", "-", request, False)
            return _login_page("محاولات كثيرة من هذا الجهاز. حاول بعد 15 دقيقة.", 429)
        form = await _form(request)
        username = form.get("username", "").strip().lower()[:32]
        result, user = accounts.authenticate(username, form.get("password", ""),
                                             form.get("code", ""))
        if result == "mfa_required":
            return _login_page(need_code=True, username=username)
        if result in ("ok", "setup") and user is not None:
            sid = accounts.new_session(
                user.username, stage="full" if result == "ok" else "setup", ip=ip,
                user_agent=request.headers.get("user-agent", ""))
            audit_auth("login_success" if result == "ok" else "login_setup_started",
                       user.username, request, True, f"role={user.role}")
            resp = RedirectResponse("/" if result == "ok" else "/auth/setup",
                                    status_code=303)
            _set_cookie(resp, request, sid)
            return resp
        failures[ip].append(time.time())
        audit_auth("login_failed", username or "-", request, False, f"reason={result}")
        if result == "locked":
            return _login_page("الحساب مقفول مؤقتًا بعد محاولات خاطئة. حاول بعد 15 دقيقة.", 423)
        if result == "disabled":
            return _login_page("هذا الحساب معطّل. تواصل مع المدير.", 403)
        if result == "bad_code":
            return _login_page("رمز التحقق غير صحيح.", 401, need_code=True,
                               username=username)
        return _login_page("اسم المستخدم أو كلمة المرور غير صحيحة.", 401)

    # -- first-login setup -------------------------------------------------------
    def _setup_session(request: Request):
        sess = accounts.session(request.cookies.get(cookie))
        if sess is None or sess.stage != "setup":
            raise HTTPException(status_code=401, detail="setup session expired")
        return sess

    @app.get("/auth/setup", response_class=HTMLResponse)
    def auth_setup(request: Request) -> Response:
        try:
            sess = _setup_session(request)
        except HTTPException:
            return RedirectResponse("/login", status_code=303)
        user = accounts.get(sess.username)
        secret = accounts.totp_secret(sess.username)
        return HTMLResponse(pages.account_setup(
            username=sess.username, secret=secret,
            uri=otpauth_uri(secret, sess.username), csrf=sess.csrf,
            must_change=bool(user and user.must_change),
            mfa_enabled=bool(user and user.mfa_enabled)))

    @app.post("/auth/setup", response_class=HTMLResponse)
    async def auth_setup_post(request: Request) -> Response:
        sess = _setup_session(request)
        form = await _form(request)
        if not hmac.compare_digest(form.get("csrf", ""), sess.csrf):
            raise HTTPException(status_code=403, detail="csrf check failed")
        user = accounts.get(sess.username)
        new_pw = form.get("new_password", "")
        error = ""
        if user and user.must_change and new_pw != form.get("confirm_password", ""):
            error = "كلمتا المرور غير متطابقتين"
        else:
            try:
                accounts.complete_setup(sess.username, new_pw or None,
                                        form.get("code", ""))
            except AccountError as exc:
                error = str(exc)
        if error:
            secret = accounts.totp_secret(sess.username)
            return HTMLResponse(pages.account_setup(
                username=sess.username, secret=secret,
                uri=otpauth_uri(secret, sess.username), csrf=sess.csrf,
                must_change=bool(user and user.must_change),
                mfa_enabled=bool(user and user.mfa_enabled), error=error),
                status_code=422)
        accounts.revoke(request.cookies.get(cookie))
        sid = accounts.new_session(sess.username, stage="full", ip=client_ip(request),
                                   user_agent=request.headers.get("user-agent", ""))
        audit_auth("login_setup_completed", sess.username, request, True,
                   "mfa_enrolled password_set" if user and user.must_change
                   else "mfa_enrolled")
        resp = RedirectResponse("/", status_code=303)
        _set_cookie(resp, request, sid)
        return resp

    # -- logout ----------------------------------------------------------------
    @app.post("/auth/logout")
    def auth_logout(request: Request) -> Response:
        actor = guard(request)
        accounts.revoke(request.cookies.get(cookie))
        audit_auth("logout", actor, request, True)
        resp = Response(status_code=204, headers={"HX-Redirect": "/login"})
        resp.delete_cookie(cookie, path="/")
        return resp

    # -- user administration (admin) ------------------------------------------
    def _users_page(request: Request, notice: str = "", error: str = "",
                    status: int = 200) -> HTMLResponse:
        store = app.state.store
        events = []
        if store is not None:
            events = store.query(
                "SELECT ts, action_type, target_ip, verdict, detail FROM actions"
                " WHERE case_id = 'auth' ORDER BY id DESC LIMIT 60")
        return HTMLResponse(pages.users_admin(
            users=accounts.list(), sessions=accounts.active_sessions(),
            events=events, roles=ROLES, me=request.state.actor,
            notice=notice, error=error, idle_minutes=IDLE_SECONDS // 60),
            status_code=status)

    @app.get("/ui/users", response_class=HTMLResponse)
    def ui_users(request: Request) -> HTMLResponse:
        guard(request, "admin")
        return _users_page(request)

    @app.get("/ui/access", response_class=HTMLResponse)
    def ui_access(request: Request) -> HTMLResponse:
        """Sign-in history for every analyst (read-only, admin)."""
        guard(request, "admin")
        return _users_page(request)

    @app.post("/users/action", response_class=HTMLResponse)
    async def users_action(request: Request) -> HTMLResponse:
        actor = guard(request, "admin")
        form = await _form(request)
        op, target = form.get("op", ""), form.get("username", "").strip().lower()
        try:
            if op == "create":
                accounts.create(target, form.get("role", ""), form.get("password", ""))
                note = f"تم إنشاء {target}: يدخل بكلمة المرور المؤقتة ثم يفعّل التحقق بخطوتين"
            elif op == "role":
                if target == actor and form.get("role") != "admin":
                    raise AccountError("لا يمكنك تخفيض صلاحياتك بنفسك")
                accounts.set_role(target, form.get("role", ""))
                note = f"تم تغيير دور {target}"
            elif op in ("disable", "enable"):
                if target == actor:
                    raise AccountError("لا يمكنك تعطيل حسابك بنفسك")
                accounts.set_disabled(target, op == "disable")
                note = f"تم {'تعطيل' if op == 'disable' else 'تفعيل'} {target}"
            elif op == "reset_password":
                accounts.reset_password(target, form.get("password", ""))
                note = f"تم تعيين كلمة مرور مؤقتة لـ {target}"
            elif op == "reset_mfa":
                accounts.reset_mfa(target)
                note = f"تم إلغاء التحقق بخطوتين لـ {target}؛ سيعيد تفعيله عند الدخول"
            elif op == "logout_all":
                accounts.revoke_user_sessions(target)
                note = f"تم إنهاء كل جلسات {target}"
            else:
                raise AccountError("عملية غير معروفة")
        except AccountError as exc:
            audit_auth(f"user_{op or 'unknown'}", actor, request, False,
                       f"target={target} error={exc}")
            return _users_page(request, error=str(exc), status=422)
        audit_auth(f"user_{op}", actor, request, True,
                   f"target={target} role={form.get('role', '')}")
        return _users_page(request, notice=note)
