"""P2 — critical escalation: urgent notice, deadline, ack, auto-remediation."""
from __future__ import annotations

import json
import threading
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest
import yaml

from sentinel.actuation import Executor
from sentinel.auditstore.store import Store
from sentinel.decision.chain import Facts
from sentinel.escalation import CriticalWatch
from sentinel.notify.approvals import TelegramApprovals
from sentinel.validator import Validator
from tests.fixtures.decision.helpers import (FakeClock, IncidentStub, alert,
                                              config_view, engine as make_engine)
from tests.test_executor import FakeActuator

CFG = Path(__file__).parent / "fixtures" / "valid_config.yaml"


class Inc(IncidentStub):
    src_ip = "198.51.100.7"


class FakeHub:
    def __init__(self):
        self.sent = []

    def notify_urgent(self, n):
        self.sent.append(n)
        return True


class FakeLocked:
    """Engine facade with the clock exposed, like the real daemon wiring."""

    def __init__(self, eng):
        self.e = eng

    def pending_approvals(self):
        return self.e.pending_approvals()

    def resolve(self, *a, **kw):
        return self.e.resolve(*a, **kw)


def world(tmp_path, *, minutes=30, auto=True, level=2, dry_run=False,
          min_score=0.70, reminder_s=300):
    clk = FakeClock()
    eng, _ = make_engine(cfg=config_view(critical_min_score=min_score,
                                         critical_window_s=minutes * 60,
                                         auto_threshold=0.95), clock=clk)
    store = Store(tmp_path / "a.sqlite", check_same_thread=False)
    hub = FakeHub()
    acts = {"nftables_local": FakeActuator("nftables_local")}
    ex = Executor(store=store, validator=Validator(config_view()),
                  actuators=acts, autonomy_level=lambda: level,
                  dry_run=dry_run, clock=lambda: clk().timestamp())
    recorded = []
    watch = CriticalWatch(store=store, engine=FakeLocked(eng), hub=hub,
                          executor=ex, clock=clk, auto_remediate=auto,
                          reminder_s=reminder_s,
                          record_decision=lambda d, case: recorded.append((d, case)))
    return eng, clk, store, hub, ex, acts, watch, recorded


def critical_decision(eng):
    inc = Inc([alert("auth_fail_burst", 0.93, crit="critical")])
    d = eng.evaluate(inc, Facts(liveness="alive"))
    return d, {"incident_id": d.incident_id, "src_ip": "198.51.100.7", "dst_ip": "10.0.0.99"}


def audits(store):
    return [r["verdict"] for r in store.rows("actions") if r["case_id"] == "escalation"]


# -- engine side --------------------------------------------------------------------

def test_critical_gets_the_long_window_and_a_flag(tmp_path):
    eng, clk, *_ = world(tmp_path, minutes=30)
    d, _ = critical_decision(eng)
    assert d.inputs["critical"] is True and d.outcome.value == "human_approval"
    assert d.approval_deadline == clk() + timedelta(minutes=30)


def test_non_critical_keeps_the_normal_window(tmp_path):
    eng, clk, *_ = world(tmp_path, minutes=30, min_score=0.90)
    d, _ = critical_decision(eng)                       # score .744 < .90
    assert d.inputs["critical"] is False
    assert d.approval_deadline == clk() + timedelta(minutes=15)


def test_engineer_can_still_approve_after_minute_16_on_a_critical_case(tmp_path):
    eng, clk, *_ = world(tmp_path, minutes=30)
    d, _ = critical_decision(eng)
    clk.advance(minutes=20)
    r = eng.resolve(d.incident_id, True)
    assert r.outcome.value == "auto_act"                # not a timeout


# -- urgent notice ----------------------------------------------------------------------

def test_urgent_message_says_what_when_and_what_happens_at_the_deadline(tmp_path):
    eng, clk, store, hub, ex, acts, watch, _ = world(tmp_path, minutes=30)
    d, ctx = critical_decision(eng)
    assert watch.consider(d, ctx) is True
    n = hub.sent[0]
    assert n.severity == "critical" and n.approval_id == d.incident_id
    assert "198.51.100.7" in n.body and "/approve" in n.body and "/ack" in n.body
    assert "سينفّذ Sentinel بنفسه" in n.body and "30 دقيقة" in n.body
    assert audits(store) == ["critical_escalation_opened"]
    assert watch.consider(d, ctx) is False             # no duplicate escalation


def test_non_human_approval_decisions_never_open_an_escalation(tmp_path):
    eng, clk, store, hub, ex, acts, watch, _ = world(tmp_path)
    inc = Inc([alert("scan", 0.3, crit="low")])
    d = eng.evaluate(inc, Facts(liveness="alive"))
    assert watch.consider(d, {"incident_id": d.incident_id}) is False
    assert hub.sent == []


def test_reminders_repeat_until_someone_acts(tmp_path):
    eng, clk, store, hub, ex, acts, watch, _ = world(tmp_path, minutes=30, reminder_s=300)
    d, ctx = critical_decision(eng)
    watch.consider(d, ctx)
    clk.advance(minutes=5, seconds=1)
    watch.tick()
    clk.advance(minutes=5, seconds=1)
    watch.tick()
    titles = [n.title for n in hub.sent]
    assert titles[0].startswith("حالة حرجة") and len(titles) == 3
    assert "باقي 24 دقيقة" in titles[1] or "باقي 25 دقيقة" in titles[1]


# -- what happens at the deadline ------------------------------------------------------------

def test_nobody_acts_so_the_system_acts_through_all_gates(tmp_path):
    eng, clk, store, hub, ex, acts, watch, rec = world(tmp_path, minutes=15)
    d, ctx = critical_decision(eng)
    watch.consider(d, ctx)
    clk.advance(minutes=14)
    assert watch.tick() == 0 and not acts["nftables_local"].calls
    clk.advance(minutes=2)
    assert watch.tick() == 1
    call = acts["nftables_local"].calls[0]
    assert call.target_ip == "198.51.100.7" and call.ttl_minutes == 30   # attacker, G3
    decision, case = rec[0]
    assert case == "deadline"
    assert "critical_deadline_auto_action" in [e.name for e in decision.audit_events]
    row = store.rows("actions")[-2]                      # executor row before the audit row
    assert row["case_id"] == "deadline" and row["executed"] == 1
    assert "critical_deadline_auto_action" in audits(store)
    assert "تصرّف تلقائي" in hub.sent[-1].title
    assert eng.pending_approvals() == {}


def test_deadline_action_still_obeys_autonomy_and_dry_run(tmp_path):
    for kwargs, expect in (({"level": 1}, "withheld_autonomy"),
                           ({"dry_run": True}, "dry_run")):
        sub = tmp_path / expect
        sub.mkdir()
        eng, clk, store, hub, ex, acts, watch, _ = world(sub, minutes=15, **kwargs)
        d, ctx = critical_decision(eng)
        watch.consider(d, ctx)
        clk.advance(minutes=16)
        watch.tick()
        assert not acts["nftables_local"].calls
        assert expect in [r["verdict"] for r in store.rows("actions")]
        store.close()


def test_human_decision_before_the_deadline_cancels_auto_action(tmp_path):
    eng, clk, store, hub, ex, acts, watch, rec = world(tmp_path, minutes=15)
    d, ctx = critical_decision(eng)
    watch.consider(d, ctx)
    eng.resolve(d.incident_id, False)                  # engineer says NO
    watch.resolved(d.incident_id)
    clk.advance(minutes=30)
    assert watch.tick() == 0 and not acts["nftables_local"].calls and rec == []
    assert "critical_escalation_closed" in audits(store)


def test_ack_stops_the_automatic_action_but_keeps_pressure(tmp_path):
    eng, clk, store, hub, ex, acts, watch, rec = world(tmp_path, minutes=15)
    d, ctx = critical_decision(eng)
    watch.consider(d, ctx)
    assert watch.ack(d.incident_id, "eng-ali") is True
    assert watch.ack(d.incident_id, "other") is False
    clk.advance(minutes=16)
    assert watch.tick() == 0 and not acts["nftables_local"].calls
    assert "انتهت المهلة" in hub.sent[-1].title and "eng-ali" in hub.sent[-1].body
    assert {"critical_acknowledged", "critical_deadline_passed"} <= set(audits(store))


def test_auto_remediation_can_be_switched_off(tmp_path):
    eng, clk, store, hub, ex, acts, watch, rec = world(tmp_path, minutes=15, auto=False)
    d, ctx = critical_decision(eng)
    watch.consider(d, ctx)
    assert "لن يتصرف النظام تلقائيًا" in hub.sent[0].body
    clk.advance(minutes=16)
    assert watch.tick() == 0 and not acts["nftables_local"].calls


def test_g1_protected_escalations_are_never_auto_acted(tmp_path):
    eng, clk, store, hub, ex, acts, watch, rec = world(tmp_path)
    eng._cfg = config_view(critical_min_score=0.7, critical_window_s=900,
                           critical_assets=frozenset({"198.51.100.7"}))
    inc = Inc([alert("auth_fail_burst", 0.97, crit="critical")])
    d = eng.evaluate(inc, Facts(liveness="alive"))
    assert d.outcome.value == "escalate_human"          # G1: the target is protected
    assert watch.consider(d, {"incident_id": d.incident_id}) is False
    clk.advance(minutes=60)
    assert watch.tick() == 0 and not acts["nftables_local"].calls


# -- telegram ack ---------------------------------------------------------------------------------

def test_telegram_ack_command(monkeypatch):
    monkeypatch.setenv("TG", "1:a")
    api = {"result": [{"update_id": 1, "message": {"chat": {"id": 42}, "text": "/ack inc-9"}},
                      {"update_id": 2, "message": {"chat": {"id": 42}, "text": "/approve inc-9"}},
                      {"update_id": 3, "message": {"chat": {"id": 7}, "text": "/ack inc-9"}}]}
    ap = TelegramApprovals("TG", "42", fetch=lambda u, t: api)
    assert ap.poll_once() == [("inc-9", None), ("inc-9", True)]


# -- full path through the daemon with a real HTTP SOAR ----------------------------------------------

class _Soar(BaseHTTPRequestHandler):
    got = []

    def do_POST(self):
        _Soar.got.append(json.loads(self.rfile.read(int(self.headers["Content-Length"]))))
        self.send_response(200)
        self.end_headers()

    def log_message(self, *a):
        pass


def test_daemon_end_to_end_critical_ddos_with_no_engineer(tmp_path):
    from sentinel.config.loader import load_config
    from sentinel.daemon import build_daemon
    _Soar.got = []
    srv = HTTPServer(("127.0.0.1", 0), _Soar)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    try:
        cfg = yaml.safe_load(CFG.read_text())
        cfg["audit_store"] = {"path": str(tmp_path / "a.sqlite")}
        cfg["autonomy_level"] = 2
        cfg["critical_response"] = {"enabled": True, "min_score": 0.70,
                                    "deadline_minutes": 15, "reminder_minutes": 5}
        cfg["actuators"] = [{"type": "webhook_soar",
                             "url": f"http://127.0.0.1:{srv.server_address[1]}/hook"}]
        cp = tmp_path / "c.yaml"
        cp.write_text(yaml.safe_dump(cfg))
        store = Store(tmp_path / "a.sqlite")
        d = build_daemon(load_config(cp), tmp_path, store, dry_run=False)
        now = [datetime.now(timezone.utc)]
        d._clock = lambda: now[0]
        d._engine._engine._clock = lambda: now[0]
        d._watch._clock = lambda: now[0]
        hub = FakeHub()
        d._watch._hub = hub
        base = now[0] - timedelta(seconds=40)
        hdr = ("#fields\tts\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\n"
               "#types\ttime\taddr\tport\taddr\tport\tstring\n")
        rows = "".join(
            f"{(base + timedelta(seconds=i * 0.05)).timestamp():.6f}\t192.0.2.{i % 80 + 1}"
            f"\t4000\t10.0.0.4\t443\ttcp\n" for i in range(700))
        (tmp_path / "conn.log").write_text(hdr + rows)
        d.run_once()
        dec = store.rows("decisions")[0]
        assert dec["outcome"] == "human_approval"
        assert hub.sent and "10.0.0.4" in hub.sent[0].body and _Soar.got == []
        now[0] += timedelta(minutes=16)                  # nobody answers
        d.run_once()
        assert _Soar.got and _Soar.got[0]["action"] == "recommend_upstream_mitigation"
        assert _Soar.got[0]["target_ip"] == "10.0.0.4"
        cases = [r["case_id"] for r in store.rows("decisions")]
        assert cases == ["live", "deadline"]
        act = [r for r in store.rows("actions") if r["verdict"] == "executed"]
        assert act and act[0]["case_id"] == "deadline"
        assert store.verify_chain()["ok"]
        store.close()
    finally:
        srv.shutdown()


# -- UI ----------------------------------------------------------------------------------------------

def _ui(tmp_path, monkeypatch, *, on_ack=None, status=None):
    from fastapi.testclient import TestClient
    from sentinel.ui.app import create_app
    monkeypatch.setenv("TOK_CRIT_UI", "s3")
    eng, clk, store, hub, ex, acts, watch, _ = world(tmp_path, minutes=30)
    d, ctx = critical_decision(eng)
    store.record_incident_context(
        incident_id=d.incident_id, src_ip="198.51.100.7", dst_ip="10.0.0.99",
        attack_type="Brute force", signals=["auth_fail_burst"], alert_count=3,
        first_ts="2026-10-20T08:00:00+00:00", last_ts="2026-10-20T08:01:00+00:00",
        evidence=[], mitre=[])
    app = create_app({"ops_ui": {"enabled": True, "bind": "127.0.0.1:8080",
                                 "auth_token_env": "TOK_CRIT_UI", "allowed_ports": [8080]}},
                     engine=eng, store=store, on_ack=on_ack, critical_status=status)
    return TestClient(app), d, eng


def test_ui_shows_critical_badge_countdown_and_ack_button(tmp_path, monkeypatch):
    seen = []
    c, d, _ = _ui(tmp_path, monkeypatch, on_ack=lambda i: seen.append(i) or True,
                  status=lambda i: {"acked_by": None})
    H = {"X-Sentinel-Token": "s3"}
    html = c.get("/ui/approvals", headers=H).text
    assert "حرج" in html and "باقي" in html and "استلمت الحالة" in html
    assert c.post(f"/approvals/{d.incident_id}/ack").status_code == 401
    r = c.post(f"/approvals/{d.incident_id}/ack", headers=H)
    assert r.status_code == 200 and seen == [d.incident_id]


def test_ui_ack_states(tmp_path, monkeypatch):
    H = {"X-Sentinel-Token": "s3"}
    c, d, _ = _ui(tmp_path, monkeypatch, on_ack=None)
    assert c.post(f"/approvals/{d.incident_id}/ack", headers=H).status_code == 409
    c2, d2, _ = _ui(tmp_path / "x" if (tmp_path / "x").mkdir() is None else tmp_path,
                    monkeypatch, on_ack=lambda i: False)
    assert c2.post(f"/approvals/{d2.incident_id}/ack", headers=H).status_code == 404


def test_ui_shows_who_acknowledged(tmp_path, monkeypatch):
    c, d, _ = _ui(tmp_path, monkeypatch, on_ack=lambda i: True,
                  status=lambda i: {"acked_by": "eng-ali"})
    html = c.get("/ui/approvals", headers={"X-Sentinel-Token": "s3"}).text
    assert "استلمها eng-ali" in html and "استلمت الحالة" not in html
