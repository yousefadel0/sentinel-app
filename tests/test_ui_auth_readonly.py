"""M7 auth gate (P1/P2) + read-only views + KPI name pin (Q1 verbatim).

Route/auth matrix exercised here mirrors DELIVERY-M7.md:
    GET  /static/htmx.min.js            NO AUTH   (DP2 sole exception)
    GET  /                              token
    GET  /health/capture                token
    GET  /approvals                     token
    POST /approvals/{id}/approve|deny   token     (writes via Engine.resolve)
    GET  /incidents/recent              token
    GET  /kpis                          token
"""
from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sentinel.decision.chain import Facts  # noqa: E402
from sentinel.ui.app import create_app  # noqa: E402
from sentinel.ui.views import kpis  # noqa: E402


TOKEN_ENV = "SENTINEL_TEST_OPS_UI_TOKEN"


def _full_cfg() -> dict:
    """create_app receives the FULL validated config (ops_ui nested)."""
    return {"ops_ui": {"enabled": True,
                       "bind": "127.0.0.1:8080",
                       "auth_token_env": TOKEN_ENV,
                       "allowed_ports": [8080]}}


@pytest.fixture()
def client(monkeypatch):
    monkeypatch.setenv(TOKEN_ENV, "s3cret")
    from fastapi.testclient import TestClient
    from sentinel.auditstore.store import Store
    # Embedded-style deployment: empty-but-real store attached.
    app = create_app(_full_cfg(),
                     store=Store(Path(tempfile.mkdtemp()) / "a.sqlite",
                     check_same_thread=False))
    return TestClient(app)


H = {"X-Sentinel-Token": "s3cret"}


# -- auth gate ------------------------------------------------------------ #
def test_missing_token_is_401_fail_closed(client):
    assert client.get("/kpis").status_code == 401


def test_wrong_token_is_401_constant_time_compare_path(client):
    r = client.get("/kpis", headers={"X-Sentinel-Token": "wrong"})
    assert r.status_code == 401


def test_correct_header_token_grants_access(client):
    assert client.get("/kpis", headers=H).status_code == 200


def test_latest_report_route_is_authenticated_and_serves_report(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient
    report_dir = tmp_path / "reports"
    report_dir.mkdir()
    (report_dir / "latest.html").write_text("<html>latest</html>", encoding="utf-8")
    monkeypatch.setenv(TOKEN_ENV, "s3cret")
    app = create_app(_full_cfg(), report_dir=report_dir)
    test_client = TestClient(app)
    assert test_client.get("/reports/latest").status_code == 401
    response = test_client.get("/reports/latest", headers=H)
    assert response.status_code == 200
    assert "latest" in response.text
    assert response.headers["content-disposition"].startswith("inline")
    assert "فتح تقرير آخر تشغيل" in test_client.get(
        "/dashboard/report", headers=H).text


def test_token_in_query_string_is_rejected_not_accepted(client):
    """Header-only transport (DP3): never accept ?token=..."""
    r = client.get("/kpis?token=s3cret")
    assert r.status_code == 401


def test_htmx_static_asset_is_the_sole_unauthenticated_route(client):
    assert client.get("/static/htmx.min.js").status_code == 200
    assert client.get("/static/other.js").status_code in (401, 404)
    # every other route stays gated even with no token at all:
    for path in ("/", "/health/capture", "/approvals",
                 "/incidents/recent", "/kpis"):
        assert client.get(path).status_code == 401, path


# -- read-only views ------------------------------------------------------ #
def test_kpis_endpoint_returns_p5_names_exactly(client):
    """Q1 pin: the five P5 KPI names present verbatim (superset allowed —
    compute_kpis is M6-owned; UI must not rename or drop any)."""
    body = client.get("/kpis", headers=H).json()
    assert {"incidents", "mttd_seconds", "mttd_replay_seconds",
            "fp_rate", "llm_latency_ms"} <= set(body)
    # exact-name spot checks (no blended mttd name anywhere):
    assert "mttd" not in set(body)          # never a bare/blended name
    assert body["mttd_seconds"] == {"n": 0, "avg": None}   # honest zeros


def test_views_kpis_delegates_to_compute_kpis_verbatim():
    from sentinel.auditstore.store import Store
    s = Store(Path(tempfile.mkdtemp()) / "a.sqlite")
    k = kpis(s)
    from sentinel.pilot.kpi import compute_kpis
    assert k == compute_kpis(s)


def test_recent_incidents_read_only_store(tmp_path):
    """Store.query is SELECT-only; UI must not mutate the audit store."""
    from sentinel.ui.views import recent_incidents
    from sentinel.auditstore.store import Store
    db = tmp_path / "a.sqlite"
    s = Store(db)
    rows_before = len(s.rows("decisions"))
    recent_incidents(s, limit=20)
    assert len(Store(db).rows("decisions")) == rows_before


# -- approval writes go through the SAME seam as CLI ---------------------- #
def _engine_with_pending_approval():
    from tests.fixtures.decision.helpers import (
        FakeClock, IncidentStub, alert, engine,
    )
    eng, clk = engine(clock=FakeClock())
    d = eng.evaluate(IncidentStub([alert("auth_fail_burst", 0.93,
                                         crit="critical")]),
                     Facts(liveness="alive"))
    return eng, clk, d


def test_approve_route_resolves_via_engine_and_records_decision(
        monkeypatch, tmp_path):
    monkeypatch.setenv(TOKEN_ENV, "s3cret")
    eng, clk, d = _engine_with_pending_approval()
    from fastapi.testclient import TestClient
    from sentinel.auditstore.store import Store
    app = create_app(_full_cfg(), engine=eng,
                     store=Store(tmp_path / "a.sqlite",
                                 check_same_thread=False))
    c = TestClient(app)
    r = c.post(f"/approvals/{d.incident_id}/approve", headers=H)
    assert r.status_code == 200
    body = r.json()
    assert body["approval_id"] == d.incident_id
    # Route resolved via Engine.resolve (same seam as CLI) and recorded:
    rows = Store(tmp_path / "a.sqlite").rows("decisions")
    assert len(rows) == 1
    rec_row = rows[0]
    assert rec_row["incident_id"] == d.incident_id
    events = json.loads(rec_row["audit_events"]) if isinstance(
        rec_row.get("audit_events"), str) else rec_row["audit_events"]
    names = [e["name"] for e in events]
    assert "human_approval_granted" in names


def test_standalone_mode_refuses_approval_writes_409(monkeypatch):
    """No engine/store attached → observer mode; writes refused."""
    monkeypatch.setenv(TOKEN_ENV, "s3cret")
    from fastapi.testclient import TestClient
    c = TestClient(create_app(_full_cfg()))
    r = c.post("/approvals/inc-1/approve",
               headers={"X-Sentinel-Token": "s3cret"})
    assert r.status_code == 409
