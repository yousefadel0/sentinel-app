"""Accounts mode: named users, roles, MFA, CSRF, lockout, audited sign-ins."""
import re
import time
from pathlib import Path

import pytest
import yaml
from fastapi.testclient import TestClient

from sentinel.auditstore.store import Store
from sentinel.config.loader import load_config
from sentinel.learning import LearningProfile
from sentinel.ui import accounts as acc
from sentinel.ui.accounts import AccountError, AccountStore, totp_now
from sentinel.ui.app import create_app

PW = "correct-horse-battery-9"


def _app(tmp_path, monkeypatch, **ui):
    monkeypatch.delenv("SENTINEL_OPS_UI_TOKEN", raising=False)
    config = yaml.safe_load(Path("tests/fixtures/valid_config.yaml").read_text())
    config["ops_ui"].update({"enabled": True, "auth_mode": "accounts", **ui})
    config["audit_store"] = {"path": str(tmp_path / "audit.sqlite")}
    path = tmp_path / "config.yaml"
    path.write_text(yaml.safe_dump(config), encoding="utf-8")
    store = Store(tmp_path / "audit.sqlite", check_same_thread=False)
    LearningProfile(tmp_path / "learning.json")
    app = create_app(load_config(path), store=store, capture_dir=tmp_path,
                     report_dir=tmp_path / "reports", config_path=path)
    return app, store


def _enrolled(app, username, role):
    """Create a user and complete first-login setup; returns a logged-in client."""
    accounts: AccountStore = app.state.accounts
    accounts.create(username, role, PW + "-tmp")
    client = TestClient(app)
    r = client.post("/auth/login", data={"username": username, "password": PW + "-tmp"},
                    follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/auth/setup"
    page = client.get("/auth/setup").text
    csrf = re.search(r'name="csrf" value="([^"]+)"', page).group(1)
    secret = accounts.totp_secret(username)
    r = client.post("/auth/setup", data={"csrf": csrf, "new_password": PW,
                                         "confirm_password": PW,
                                         "code": totp_now(secret)},
                    follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/"
    shell = client.get("/").text
    token = re.search(r'name="csrf-token" content="([^"]+)"', shell).group(1)
    client.headers["X-CSRF-Token"] = token
    return client


def test_no_session_means_no_data_and_redirect_to_login(tmp_path, monkeypatch):
    app, store = _app(tmp_path, monkeypatch)
    c = TestClient(app)
    assert c.get("/", follow_redirects=False).status_code == 303
    for route in ("/ui/overview", "/ui/incidents", "/ui/users", "/audit/export.csv"):
        assert c.get(route).status_code == 401
    assert "sentinel ctl user add" in c.get("/login").text      # first-run hint
    store.close()


def test_token_header_is_refused_in_accounts_mode(tmp_path, monkeypatch):
    app, store = _app(tmp_path, monkeypatch)
    monkeypatch.setenv("SENTINEL_OPS_UI_TOKEN", "x" * 40)
    c = TestClient(app)
    assert c.get("/ui/overview", headers={"X-Sentinel-Token": "x" * 40}).status_code == 401
    store.close()


def test_first_login_enrols_mfa_then_requires_code(tmp_path, monkeypatch):
    app, store = _app(tmp_path, monkeypatch)
    client = _enrolled(app, "manager", "admin")
    assert client.get("/ui/overview").status_code == 200
    assert "manager" in client.get("/").text
    fresh = TestClient(app)
    r = fresh.post("/auth/login", data={"username": "manager", "password": PW})
    assert 'name="code"' in r.text                               # MFA now required
    assert fresh.get("/ui/overview").status_code == 401
    events = [row[0] for row in store.query(
        "SELECT action_type FROM actions WHERE case_id = 'auth'")]
    assert "login_setup_completed" in events
    assert store.verify_chain()["ok"]
    store.close()


def test_roles_are_enforced_server_side(tmp_path, monkeypatch):
    app, store = _app(tmp_path, monkeypatch)
    viewer = _enrolled(app, "watcher", "viewer")
    analyst = _enrolled(app, "analyst1", "analyst")
    admin = _enrolled(app, "boss", "admin")
    assert viewer.get("/ui/incidents").status_code == 200
    assert viewer.post("/approvals/x/approve").status_code == 403
    assert viewer.post("/learning/mode", data={"mode": "active"}).status_code == 403
    assert analyst.post("/learning/mode", data={"mode": "active"}).status_code == 403
    assert analyst.get("/ui/users").status_code == 403
    assert admin.get("/ui/users").status_code == 200
    assert admin.post("/learning/extend", data={"days": "2"}).status_code == 200
    detail = store.query("SELECT detail FROM actions WHERE action_type ="
                         " 'learning_extend_days'")[0][0]
    assert "by=boss" in detail                                   # named actor
    store.close()


def test_csrf_token_required_on_writes(tmp_path, monkeypatch):
    app, store = _app(tmp_path, monkeypatch)
    admin = _enrolled(app, "boss", "admin")
    del admin.headers["X-CSRF-Token"]
    assert admin.post("/learning/extend", data={"days": "1"}).status_code == 403
    admin.headers["X-CSRF-Token"] = "forged"
    assert admin.post("/learning/extend", data={"days": "1"}).status_code == 403
    store.close()


def test_lockout_after_repeated_failures(tmp_path, monkeypatch):
    app, store = _app(tmp_path, monkeypatch)
    _enrolled(app, "boss", "admin")
    c = TestClient(app)
    for _ in range(acc.MAX_FAILED):
        c.post("/auth/login", data={"username": "boss", "password": "wrong-password-123"})
    r = c.post("/auth/login", data={"username": "boss", "password": PW, "code": "000000"})
    assert r.status_code == 423
    failed = store.query("SELECT COUNT(*) FROM actions WHERE action_type = 'login_failed'")
    assert failed[0][0] >= acc.MAX_FAILED
    store.close()


def test_logout_revokes_the_session(tmp_path, monkeypatch):
    app, store = _app(tmp_path, monkeypatch)
    admin = _enrolled(app, "boss", "admin")
    r = admin.post("/auth/logout")
    assert r.status_code == 204 and r.headers["HX-Redirect"] == "/login"
    assert admin.get("/ui/overview").status_code == 401
    store.close()


def test_admin_manages_users_and_cannot_lock_himself_out(tmp_path, monkeypatch):
    app, store = _app(tmp_path, monkeypatch)
    admin = _enrolled(app, "boss", "admin")
    r = admin.post("/users/action", data={"op": "create", "username": "eng1",
                                          "role": "analyst", "password": PW})
    assert r.status_code == 200 and "eng1" in r.text
    assert admin.post("/users/action", data={"op": "disable",
                                             "username": "boss"}).status_code == 422
    assert admin.post("/users/action", data={"op": "role", "username": "boss",
                                             "role": "viewer"}).status_code == 422
    assert admin.post("/users/action", data={"op": "disable",
                                             "username": "eng1"}).status_code == 200
    assert app.state.accounts.get("eng1").disabled
    store.close()


def test_security_headers(tmp_path, monkeypatch):
    app, store = _app(tmp_path, monkeypatch)
    r = TestClient(app).get("/login")
    assert r.headers["X-Frame-Options"] == "DENY"
    assert "frame-ancestors 'none'" in r.headers["Content-Security-Policy"]
    assert r.headers["Cache-Control"] == "no-store"
    store.close()


# -- account store units --------------------------------------------------------
def test_password_policy_and_hashing(tmp_path):
    s = AccountStore(tmp_path / "a.sqlite")
    with pytest.raises(AccountError):
        s.create("bob", "admin", "short")
    with pytest.raises(AccountError):
        s.create("bob", "admin", "bob-password-1234")
    s.create("bob", "admin", PW)
    raw = s._db.execute("SELECT pw_hash FROM users").fetchone()[0]
    assert raw.startswith("scrypt$") and PW not in raw
    s.close()


def test_totp_code_cannot_be_replayed(tmp_path):
    now = [time.time()]
    s = AccountStore(tmp_path / "a.sqlite", clock=lambda: now[0])
    s.create("bob", "admin", PW)
    secret = s.totp_secret("bob")
    s.complete_setup("bob", PW + "-new", totp_now(secret, now[0]))
    now[0] += 31
    code = totp_now(secret, now[0])
    assert s.authenticate("bob", PW + "-new", code)[0] == "ok"
    assert s.authenticate("bob", PW + "-new", code)[0] == "bad_code"    # replay
    s.close()


def test_last_admin_is_protected(tmp_path):
    s = AccountStore(tmp_path / "a.sqlite")
    s.create("boss", "admin", PW)
    with pytest.raises(AccountError):
        s.set_disabled("boss", True)
    with pytest.raises(AccountError):
        s.set_role("boss", "viewer")
    s.close()


def test_session_idle_timeout(tmp_path):
    now = [1_000_000.0]
    s = AccountStore(tmp_path / "a.sqlite", clock=lambda: now[0])
    s.create("bob", "viewer", PW)
    sid = s.new_session("bob")
    assert s.session(sid) is not None
    now[0] += acc.IDLE_SECONDS + 1
    assert s.session(sid) is None
    s.close()
