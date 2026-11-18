"""Ops UI v2 — pages, filters, analyst annotations, security invariants."""
from __future__ import annotations

import json
import os
import time
from pathlib import Path

import pytest

from sentinel.auditstore.store import Store
from sentinel.ui import analytics
from sentinel.ui.app import create_app

TOKEN_ENV = "SENTINEL_TEST_OPS_UI_TOKEN_V2"
H = {"X-Sentinel-Token": "s3cret"}
CFG = {"ops_ui": {"enabled": True, "bind": "127.0.0.1:8080",
                  "auth_token_env": TOKEN_ENV, "allowed_ports": [8080]},
       "autonomy_level": 0,
       "limits": {"max_blocks_per_min": 5, "max_blocks_per_hour": 20,
                  "default_ttl_min": 30},
       "site": {"name": "lab", "critical_assets": [
           {"ip": "10.0.0.4", "hostname": "dc-01"}]},
       "monitored_vlans": ["prod"], "placement": {"asymmetric_risk": "low"},
       "brain": {"llm_endpoint_env": "SENTINEL_LLM_API_SECRETISH"},
       "notifiers": [{"type": "webhook", "url_env": "SLACK_URL_X"}]}


def _seed(store):
    plan = [("inc-a", "scan", "log_only", 0.2, "203.0.113.5", "10.0.1.1"),
            ("inc-b", "brute_force", "human_approval", 0.8, "198.51.100.7", "10.0.0.4"),
            ("inc-c", "brute_force", "notify_only", 0.5, "198.51.100.7", "10.0.0.9"),
            ("inc-d", "dns_tunneling", "log_only", 0.3, "10.0.2.77", "10.0.0.5")]
    for iid, sig, oc, sc, src, dst in plan:
        store.record_decision(
            case_id="live", incident_id=iid, outcome=oc, score=sc,
            base_score=sc, tier="B", cap_applied=None, would="would <b>x</b>",
            recommendation={"action": "notify_only"},
            audit_events=[{"name": "e", "detail": "d"}])
        store.record_incident_context(
            incident_id=iid, src_ip=src, dst_ip=dst,
            attack_type={"scan": "Network service discovery",
                         "brute_force": "Brute force",
                         "dns_tunneling": "Application layer protocol: DNS"}[sig],
            signals=[sig], alert_count=3, first_ts="2026-10-20T08:00:00+00:00",
            last_ts="2026-10-20T08:05:00+00:00",
            evidence=["eve.json#1", "<script>alert(1)</script>"],
            mitre=["T1110"])


@pytest.fixture()
def env(monkeypatch, tmp_path):
    monkeypatch.setenv(TOKEN_ENV, "s3cret")
    monkeypatch.setenv("SLACK_URL_X", "https://hooks.example/SUPERSECRETVALUE")
    from fastapi.testclient import TestClient
    store = Store(tmp_path / "a.sqlite", check_same_thread=False)
    _seed(store)
    app = create_app(CFG, store=store, capture_dir=tmp_path)
    return TestClient(app), store, tmp_path


GETS = ["/ui/mode", "/ui/overview", "/ui/incidents", "/ui/incident/inc-a",
        "/ui/approvals", "/ui/sources", "/ui/audit", "/ui/audit/verify",
        "/ui/settings"]


@pytest.mark.parametrize("route", GETS)
def test_v2_routes_fail_closed(env, route):
    c = env[0]
    assert c.get(route).status_code == 401
    assert c.get(route, headers={"X-Sentinel-Token": "no"}).status_code == 401
    assert c.get(route + "?token=s3cret").status_code == 401
    assert c.get(route, headers=H).status_code == 200


def test_annotate_requires_token(env):
    c = env[0]
    assert c.post("/incidents/inc-a/annotate", content="label=benign").status_code == 401


def test_shell_is_static_and_has_all_tabs(env):
    html = env[0].get("/", headers=H).text
    for key in ("overview", "incidents", "approvals", "sources", "audit", "settings"):
        assert f'hx-get="/ui/{key}"' in html
    assert "SUPERSECRETVALUE" not in html


def test_overview_numbers_and_honest_gate(env):
    html = env[0].get("/ui/overview", headers=H).text
    assert "198.51.100.7" in html                      # top source
    ov = analytics.overview(env[1])
    assert ov["incidents"] == 4 and ov["unreviewed"] == 4
    assert ov["analyst_fp_rate"] is None               # no verdicts => no rate
    gate = analytics.autonomy_readiness(ov, 0)
    assert gate["eligible"] is False
    assert "غير مؤهل" in html


def test_incident_filters_and_pagination(env):
    c, store, _ = env
    def rows(**q):
        return analytics.incident_list(store, **q)["rows"]
    assert {r["incident_id"] for r in rows(ip="198.51.100.7")} == {"inc-b", "inc-c"}
    assert [r["incident_id"] for r in rows(outcome="human_approval")] == ["inc-b"]
    assert [r["incident_id"] for r in rows(attack_type="Brute force", min_score=0.6)] == ["inc-b"]
    assert analytics.incident_list(store, q="'; DROP TABLE decisions;--")["total"] == 0
    assert store.count("decisions") == 4
    html = c.get("/ui/incidents?outcome=log_only", headers=H).text
    assert "inc-a" in html and "inc-b" not in html
    for i in range(30):
        store.record_decision(case_id="live", incident_id=f"bulk-{i}",
                              outcome="log_only", score=0.1, base_score=0.1,
                              tier="A", cap_applied=None, would="w",
                              recommendation={}, audit_events=[])
    p2 = analytics.incident_list(store, page=2)
    assert p2["page"] == 2 and p2["pages"] == 2 and len(p2["rows"]) == 9


def test_detail_escapes_everything(env):
    html = env[0].get("/ui/incident/inc-b", headers=H).text
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html
    assert "would &lt;b&gt;x&lt;/b&gt;" in html
    assert "attack.mitre.org/techniques/T1110/" in html


def test_annotation_flow_is_audited_and_never_touches_decisions(env):
    c, store, _ = env
    before = store.rows("decisions")
    r = c.post("/incidents/inc-a/annotate", headers=H,
               content="label=false_positive&note=scanner+of+IT+team")
    assert r.status_code == 200 and "إنذار كاذب" in r.text
    assert store.rows("decisions") == before
    note = store.rows("analyst_notes")[0]
    assert (note["label"], note["actor"]) == ("false_positive", "ops_ui")
    assert note["note"] == "scanner of IT team"
    ov = analytics.overview(store)
    assert ov["labels"]["false_positive"] == 1 and ov["analyst_fp_rate"] == 1.0
    assert analytics.incident_list(store, label="false_positive")["total"] == 1
    assert analytics.incident_list(store, label="unreviewed")["total"] == 3
    assert store.verify_chain()["ok"]                   # chained like all rows


def test_annotation_validation(env):
    c = env[0]
    post = lambda body, iid="inc-a": c.post(f"/incidents/{iid}/annotate",
                                            headers=H, content=body)
    assert post("label=hacker").status_code == 422
    assert post("label=&note=").status_code == 422
    assert post("label=benign", "ghost").status_code == 404
    assert post("note=" + "x" * 20000).status_code == 200      # truncated, safe
    assert len(env[1].rows("analyst_notes")[0]["note"]) <= 2000


def test_approvals_observer_mode_is_explicit(env):
    html = env[0].get("/ui/approvals", headers=H).text
    assert "وضع مشاهدة فقط" in html


def test_settings_redacts_secrets(env):
    html = env[0].get("/ui/settings", headers=H).text
    assert "SUPERSECRETVALUE" not in html
    assert "SLACK_URL_X" in html and "مضبوط" in html
    assert "dc-01" in html


def test_audit_page_and_chain_verify(env):
    c, store, _ = env
    assert "inc-b" in c.get("/ui/audit?outcome=human_approval", headers=H).text
    assert "السلسلة سليمة" in c.get("/ui/audit/verify", headers=H).text
    conn = __import__("sqlite3").connect(env[2] / "a.sqlite")
    for (n,) in conn.execute("SELECT name FROM sqlite_master WHERE type='trigger'").fetchall():
        conn.execute(f"DROP TRIGGER {n}")
    conn.execute("UPDATE decisions SET outcome='auto_act' WHERE id=1")
    conn.commit()
    conn.close()
    assert "تم اكتشاف مشكلة" in c.get("/ui/audit/verify", headers=H).text


def test_sources_page_live_vs_replay(env):
    c, _, tmp = env
    (tmp / "live-health.json").write_text(json.dumps({"mode": "live_shadow",
        "enforcement": {"dry_run": True}, "notifications": {"channels": 0},
        "sources": [
        {"source": "eve_json", "file": "eve.json", "status": "healthy",
         "source_type": "live_file", "packet_drops": 9}]}))
    html = c.get("/ui/sources", headers=H).text
    assert "تتبّع مباشر" in html and "9" in html
    assert "حي · shadow" in c.get("/ui/mode", headers=H).text
    old = time.time() - 300
    os.utime(tmp / "live-health.json", (old, old))
    assert "الـ daemon متوقف" in c.get("/ui/mode", headers=H).text


def test_daemon_records_incident_context(tmp_path):
    from datetime import datetime, timedelta, timezone

    from tests.test_live_capture import _append, _daemon, _eve
    base = datetime(2026, 10, 20, 8, 0, 0, tzinfo=timezone.utc)
    now = [base + timedelta(seconds=30)]
    d, store = _daemon(tmp_path, now)
    _append(tmp_path / "eve.json", _eve("2026-10-20T08:00:01+0000"))
    d.run_once()
    ctx = store.rows("incident_context")[0]
    assert ctx["src_ip"] == "203.0.113.7" and ctx["dst_ip"] == "192.168.4.11"
    evidence = json.loads(ctx["evidence"])
    alerts = [x for x in evidence if x["kind"] == "alert"]
    assert [x["ref"] for x in alerts] == ["eve.json#1"]
    assert alerts[0]["dport"] == 22 and alerts[0]["src"] == "203.0.113.7"
    # the attacker's own records double as "who talked to whom" context
    assert any(x["kind"] == "flow" for x in evidence)
    assert json.loads(ctx["mitre"]) == ["T1046"]
    store.close()
