"""Phase 2 — incident detail, audit search/export, live capture view."""
from __future__ import annotations

import json
import os
import tempfile
import time
from pathlib import Path

import pytest

from sentinel.auditstore.store import Store
from sentinel.ui.app import create_app

TOKEN_ENV = "SENTINEL_TEST_OPS_UI_TOKEN2"
H = {"X-Sentinel-Token": "s3cret"}
CFG = {"ops_ui": {"enabled": True, "bind": "127.0.0.1:8080",
                  "auth_token_env": TOKEN_ENV, "allowed_ports": [8080]}}


def _seed(store):
    for i, (oc, sc, would) in enumerate([
            ("log_only", 0.3, "weak scan"), ("human_approval", 0.8, "brute force"),
            ("log_only", 0.4, "=HYPERLINK(evil)")]):
        store.record_decision(
            case_id="live", incident_id=f"inc-{i % 2}", outcome=oc, score=sc,
            base_score=sc, tier="A", cap_applied=None, would=would,
            recommendation={"action": "notify_only"},
            audit_events=[{"name": "e", "detail": "d<script>"}])


@pytest.fixture()
def env(monkeypatch, tmp_path):
    monkeypatch.setenv(TOKEN_ENV, "s3cret")
    from fastapi.testclient import TestClient
    store = Store(tmp_path / "a.sqlite", check_same_thread=False)
    _seed(store)
    app = create_app(CFG, store=store, capture_dir=tmp_path)
    return TestClient(app), store, tmp_path


NEW_ROUTES = ["/incidents/inc-0", "/dashboard/incident/inc-0",
              "/audit/search", "/audit/export.csv"]


@pytest.mark.parametrize("route", NEW_ROUTES)
def test_new_routes_fail_closed(env, route):
    client = env[0]
    assert client.get(route).status_code == 401
    assert client.get(route, headers={"X-Sentinel-Token": "bad"}).status_code == 401
    assert client.get(route + "?token=s3cret").status_code == 401


def test_incident_detail_history_and_404(env):
    client = env[0]
    body = client.get("/incidents/inc-0", headers=H).json()
    assert [d["outcome"] for d in body["decisions"]] == ["log_only", "log_only"]
    assert body["decisions"][0]["recommendation"] == {"action": "notify_only"}
    assert client.get("/incidents/nope", headers=H).status_code == 404
    # route order: /incidents/recent still resolves to the list endpoint
    assert isinstance(client.get("/incidents/recent", headers=H).json(), list)


def test_detail_html_escapes(env):
    html = env[0].get("/dashboard/incident/inc-0", headers=H).text
    assert "d&lt;script&gt;" in html and "<script>" not in html


def test_audit_search_filters_and_sql_injection_inert(env):
    client, store, _ = env
    rows = client.get("/audit/search?outcome=human_approval", headers=H).json()
    assert len(rows) == 1 and rows[0]["incident_id"] == "inc-1"
    assert len(client.get("/audit/search?min_score=0.35", headers=H).json()) == 2
    evil = client.get("/audit/search", params={"q": "'; DROP TABLE decisions;--"},
                      headers=H)
    assert evil.status_code == 200 and evil.json() == []
    assert store.count("decisions") == 3
    assert len(client.get("/audit/search?limit=1", headers=H).json()) == 1


def test_csv_export_neutralises_formulas(env):
    r = env[0].get("/audit/export.csv", headers=H)
    assert r.headers["content-type"].startswith("text/csv")
    assert "'=HYPERLINK(evil)" in r.text and ",=HYPERLINK" not in r.text


def test_reads_do_not_mutate_store(env):
    client, store, _ = env
    before = store.rows("decisions")
    for route in NEW_ROUTES:
        client.get(route, headers=H)
    assert store.rows("decisions") == before


def test_live_health_shown_and_stale_means_down(env):
    client, _, tmp = env
    hp = tmp / "live-health.json"
    hp.write_text(json.dumps({"sources": [
        {"source": "eve_json", "file": "eve.json", "status": "healthy",
         "source_type": "live_file", "packet_drops": 5}]}))
    data = client.get("/health/capture", headers=H).json()
    assert data[0]["status"] == "healthy"
    html = client.get("/dashboard/health", headers=H).text
    assert "تتبّع مباشر" in html and "5" in html
    old = time.time() - 300
    os.utime(hp, (old, old))
    data = client.get("/health/capture", headers=H).json()
    assert data[0]["status"] == "down" and data[0]["daemon_stale"] is True
