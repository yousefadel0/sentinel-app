"""Inbox (only what matters), incident story/evidence and printable report."""
from datetime import datetime, timezone
from pathlib import Path

import yaml
from fastapi.testclient import TestClient

from sentinel.auditstore.store import Store
from sentinel.config.loader import load_config
from sentinel.ui import analytics, pages
from sentinel.ui.app import create_app

TOKEN = {"X-Sentinel-Token": "inbox-test-token"}


def _incident(store, iid, outcome, score, src, dst="10.0.0.4",
              atype="Brute force"):
    store.record_decision(case_id="live", incident_id=iid, outcome=outcome,
                          score=score, base_score=score, tier="A", cap_applied=None,
                          would="x", recommendation={}, audit_events=[])
    store.record_incident_context(
        incident_id=iid, src_ip=src, dst_ip=dst, attack_type=atype,
        signals=["auth_fail_burst"], alert_count=3,
        first_ts="2026-11-18T12:00:00+00:00", last_ts="2026-11-18T12:01:00+00:00",
        evidence=[{"kind": "alert", "ts": "2026-11-18T12:00:00+00:00", "source": "eve_json",
                   "ref": "eve.json#7", "src": src, "sport": 4000, "dst": dst, "dport": 22,
                   "proto": "tcp", "what": "ET SCAN SSH brute force [sid 2001219]"},
                  {"kind": "flow", "ts": "2026-11-18T12:00:05+00:00", "src": src, "sport": 4001,
                   "dst": "10.0.0.9", "dport": 3389, "proto": "tcp", "source": "zeek_conn",
                   "bytes": 1200, "what": "rdp S0"}],
        mitre=["T1110"])
    store.record_incident_inputs(incident_id=iid, inputs={"confidence": 0.85})


def _store(tmp_path):
    store = Store(tmp_path / "audit.sqlite", check_same_thread=False)
    _incident(store, "inc-real", "human_approval", 0.68, "203.0.113.9")
    _incident(store, "inc-real2", "report_wait", 0.40, "203.0.113.9", dst="10.0.0.5")
    _incident(store, "inc-noise", "log_only", 0.09, "10.9.9.9", atype="Unmapped event")
    _incident(store, "inc-fp", "human_approval", 0.70, "198.51.100.3")
    store.record_analyst_note(incident_id="inc-fp", actor="boss", label="false_positive")
    return store


def test_inbox_groups_attackers_and_hides_noise(tmp_path):
    store = _store(tmp_path)
    data = analytics.inbox(store, now=datetime.now(timezone.utc))
    srcs = [g["src_ip"] for g in data["attackers"]]
    assert srcs == ["203.0.113.9"]                  # noise + false positive hidden
    g = data["attackers"][0]
    assert g["incidents"] == 2 and g["targets"] == ["10.0.0.4", "10.0.0.5"]
    assert g["outcome"] == "human_approval" and g["incident_id"] == "inc-real"
    assert data["noise_total"] == 2
    store.close()


def test_incident_story_shows_evidence_and_conversations(tmp_path):
    store = _store(tmp_path)
    html = pages.incident_detail(analytics.incident_full(store, "inc-real"), True)
    assert "ماذا حدث" in html and "203.0.113.9" in html
    assert "sid 2001219" in html and "203.0.113.9:4000" in html
    assert "10.0.0.9" in html and "3389" in html     # who it also talked to
    store.close()


def test_viewer_inbox_has_no_decision_buttons():
    pending = [{"approval_id": "a1", "confidence": 0.8, "deadline": "2099-01-01T00:00:00+00:00",
                "src_ip": "1.2.3.4", "dst_ip": "10.0.0.4", "attack_type": "Brute force"}]
    data = {"hours": 24, "attackers": [], "important_incidents": 0,
            "noise_total": 0, "noise_types": []}
    assert "/approvals/a1/approve" not in pages.inbox(data, pending, role="viewer")
    assert "/approvals/a1/approve" in pages.inbox(data, pending, role="analyst")


def test_inbox_route_and_printable_report(tmp_path, monkeypatch):
    monkeypatch.setenv("SENTINEL_OPS_UI_TOKEN", TOKEN["X-Sentinel-Token"])
    config = yaml.safe_load(Path("tests/fixtures/valid_config.yaml").read_text())
    config["ops_ui"]["enabled"] = True
    store = _store(tmp_path)
    client = TestClient(create_app(load_config_dict(config, tmp_path), store=store,
                                   capture_dir=tmp_path))
    r = client.get("/ui/inbox", headers=TOKEN)
    assert r.status_code == 200 and "203.0.113.9" in r.text
    r = client.get("/incidents/inc-real/report", headers=TOKEN)
    assert r.status_code == 200
    assert "تقرير حادثة" in r.text and "window.print()" in r.text
    assert "سليم" in r.text                           # audit chain verified
    assert client.get("/incidents/nope/report", headers=TOKEN).status_code == 404
    assert client.get("/incidents/inc-real/report").status_code == 401
    store.close()


def load_config_dict(config, tmp_path):
    path = tmp_path / "cfg.yaml"
    path.write_text(yaml.safe_dump(config), encoding="utf-8")
    return load_config(path)
