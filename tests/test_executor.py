"""Enforcement path: every gate between a Decision and a real actuator."""
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
from sentinel.cli import main
from sentinel.decision.chain import Facts
from sentinel.models import ActionResult
from sentinel.validator import Validator
from tests.fixtures.decision.helpers import (FakeClock, IncidentStub, alert,
                                              config_view, engine)

CFG = Path(__file__).parent / "fixtures" / "valid_config.yaml"
CTX = {"incident_id": "inc-x", "src_ip": "203.0.113.7", "dst_ip": "10.0.0.99"}


class FakeActuator:
    def __init__(self, name, ok=True, raises=False):
        self.name, self.ok, self.raises = name, ok, raises
        self.calls, self.rollbacks = [], []

    def execute(self, action):
        self.calls.append(action)
        if self.raises:
            raise RuntimeError("boom")
        return ActionResult(ok=self.ok, actuator=self.name,
                            detail="applied" if self.ok else "nope",
                            rollback_token=f"tok:{action.target_ip}")

    def execute_upstream(self, **kw):
        self.calls.append(kw)
        return ActionResult(ok=self.ok, actuator=self.name, detail="sent",
                            rollback_token=None)

    def rollback(self, token):
        self.rollbacks.append(token)
        return ActionResult(ok=True, actuator=self.name, detail="undone")


def decision_for(signal, conf, outcome_wanted=None, crit="critical"):
    eng, _ = engine(clock=FakeClock())
    inc = IncidentStub([alert(signal, conf, crit=crit)])
    return eng, inc, eng.evaluate(inc, Facts(liveness="alive"))


def make(tmp_path, *, level=2, dry_run=False, actuators=None, **kw):
    store = Store(tmp_path / "a.sqlite")
    acts = {"nftables_local": FakeActuator("nftables_local"),
            "webhook_soar": FakeActuator("webhook_soar")}
    acts.update(actuators or {})
    t = [1000.0]
    ex = Executor(store=store, validator=Validator(config_view()),
                  actuators=acts, autonomy_level=lambda: level,
                  dry_run=dry_run, clock=lambda: t[0], **kw)
    return ex, store, acts, t


def verdicts(store):
    return [(r["verdict"], r["executed"]) for r in store.rows("actions")]


def test_ddos_auto_act_goes_upstream_to_the_victim(tmp_path):
    _, _, d = decision_for("volume_spike", 1.0)
    assert d.outcome.value == "auto_act" and d.recommendation.action == \
        "recommend_upstream_mitigation"
    ex, store, acts, _ = make(tmp_path)
    assert ex.handle(d, CTX, "auto") == "executed"
    call = acts["webhook_soar"].calls[0]
    assert call["target_ip"] == "10.0.0.99" and call["ttl_minutes"] == 30
    assert verdicts(store) == [("executed", 1)]
    assert ex.handle(d, CTX, "auto") is None              # no duplicate dispatch
    assert len(acts["webhook_soar"].calls) == 1


def test_level_zero_never_executes(tmp_path):
    _, _, d = decision_for("volume_spike", 1.0)
    ex, store, acts, _ = make(tmp_path, level=0)
    assert ex.handle(d, CTX, "auto") == "withheld_autonomy"
    assert not acts["webhook_soar"].calls
    assert verdicts(store) == [("withheld_autonomy", 0)]


def test_auto_needs_l2_but_approved_needs_only_l1(tmp_path):
    _, _, d = decision_for("volume_spike", 1.0)
    ex, _, acts, _ = make(tmp_path, level=1)
    assert ex.handle(d, CTX, "auto") == "withheld_autonomy"
    assert ex.handle(d, CTX, "approved") == "executed"
    assert len(acts["webhook_soar"].calls) == 1


def test_dry_run_is_the_default_posture_and_records_the_intent(tmp_path):
    _, _, d = decision_for("volume_spike", 1.0)
    ex, store, acts, _ = make(tmp_path, dry_run=True)
    assert ex.handle(d, CTX, "auto") == "dry_run"
    assert not acts["webhook_soar"].calls and not acts["nftables_local"].calls
    assert verdicts(store) == [("dry_run", 0)]
    assert "would run" in store.rows("actions")[0]["detail"]


def test_human_approval_then_block_through_nft_with_ttl_rollback(tmp_path):
    eng, inc, d = decision_for("auth_fail_burst", 0.93)
    assert d.outcome.value == "human_approval"
    resolved = eng.resolve(d.incident_id, True)
    assert resolved.outcome.value == "auto_act"
    ex, store, acts, t = make(tmp_path, level=1)
    ctx = {"incident_id": d.incident_id, "src_ip": "198.51.100.7",
           "dst_ip": "10.0.0.99"}
    assert ex.handle(resolved, ctx, "approved", case_id="ops_ui") == "executed"
    act = acts["nftables_local"].calls[0]
    assert act.target_ip == "198.51.100.7" and act.ttl_minutes == 30   # src, G3
    assert ex.sweep() == 0 and ex.active()
    t[0] += 31 * 60                                       # past the TTL
    assert ex.sweep() == 1
    assert acts["nftables_local"].rollbacks == ["tok:198.51.100.7"]
    assert store.rows("rollbacks")[0]["ok"] == 1 and not ex.active()


def test_denied_or_non_actionable_decisions_do_nothing(tmp_path):
    eng, _, d = decision_for("auth_fail_burst", 0.93)
    denied = eng.resolve(d.incident_id, False)
    ex, store, acts, _ = make(tmp_path)
    assert ex.handle(denied, CTX, "approved") is None
    _, _, low = decision_for("scan", 0.3, crit="low")
    assert ex.handle(low, CTX, "auto") is None
    assert verdicts(store) == [] and not acts["nftables_local"].calls


def test_g6_rejects_critical_asset_target_even_if_engine_allowed(tmp_path):
    eng, _, d = decision_for("auth_fail_burst", 0.93)
    resolved = eng.resolve(d.incident_id, True)
    ex, store, acts, _ = make(tmp_path, level=1)
    # the attacker source address is (mis)configured as a critical asset
    ex._validator = Validator(config_view(critical_assets=frozenset({"198.51.100.7"})))
    ctx = {"incident_id": "i", "src_ip": "198.51.100.7", "dst_ip": "10.0.0.99"}
    assert ex.handle(resolved, ctx, "approved") == "rejected_g6"
    assert not acts["nftables_local"].calls


def test_missing_failing_and_crashing_actuators_are_honest(tmp_path):
    eng, _, d = decision_for("auth_fail_burst", 0.93)
    resolved = eng.resolve(d.incident_id, True)
    ctx = {"incident_id": "i", "src_ip": "198.51.100.7", "dst_ip": "10.0.0.99"}
    ex, store, acts, _ = make(tmp_path, level=1, actuators={})
    del ex._actuators["nftables_local"]
    assert ex.handle(resolved, ctx, "approved") == "no_actuator"
    (tmp_path / "b").mkdir()
    (tmp_path / "c").mkdir()
    ex2, _, _, _ = make(tmp_path / "b", level=1,
                        actuators={"nftables_local": FakeActuator("n", ok=False)})
    assert ex2.handle(resolved, ctx, "approved") == "failed"
    ex3, s3, _, _ = make(tmp_path / "c", level=1,
                         actuators={"nftables_local": FakeActuator("n", raises=True)})
    assert ex3.handle(resolved, ctx, "approved") == "failed"       # no exception
    assert ex3.executed == 0 and not ex3.active()


def test_hourly_cap_limits_enforcement(tmp_path):
    ex, store, acts, t = make(tmp_path, max_per_hour=2)
    res = []
    for i in range(4):
        _, _, d = decision_for("volume_spike", 1.0)
        res.append(ex.handle(d, {"incident_id": f"i{i}", "src_ip": "1.1.1.1",
                                 "dst_ip": f"10.0.0.{i + 10}"}, "auto"))
    assert res == ["executed", "executed", "rate_limited", "rate_limited"]
    t[0] += 3601
    _, _, d = decision_for("volume_spike", 1.0)
    assert ex.handle(d, {"incident_id": "n", "src_ip": "1.1.1.1",
                         "dst_ip": "10.0.0.50"}, "auto") == "executed"


def test_rollback_all_is_the_panic_button(tmp_path):
    ex, store, acts, _ = make(tmp_path, level=1)
    eng, _, d = decision_for("auth_fail_burst", 0.93)
    r = eng.resolve(d.incident_id, True)
    ex.handle(r, {"incident_id": "i", "src_ip": "198.51.100.7", "dst_ip": "x"}, "approved")
    assert ex.rollback_all() == 1 and not ex.active()


# -- end to end through the daemon, real HTTP SOAR ---------------------------

class _Soar(BaseHTTPRequestHandler):
    received = []

    def do_POST(self):
        body = self.rfile.read(int(self.headers["Content-Length"]))
        _Soar.received.append((json.loads(body), self.headers.get("Authorization")))
        self.send_response(200)
        self.end_headers()

    def log_message(self, *a):
        pass


def _flood_daemon(tmp_path, monkeypatch, *, level, dry_run, port):
    from sentinel.config.loader import load_config
    from sentinel.daemon import build_daemon
    cfg = yaml.safe_load(CFG.read_text())
    cfg["audit_store"] = {"path": str(tmp_path / "a.sqlite")}
    cfg["autonomy_level"] = level
    cfg["actuators"] = [{"type": "webhook_soar",
                         "url": f"http://127.0.0.1:{port}/hook"}]
    cp = tmp_path / "c.yaml"
    cp.write_text(yaml.safe_dump(cfg))
    store = Store(tmp_path / "a.sqlite")
    d = build_daemon(load_config(cp), tmp_path, store, dry_run=dry_run)
    base = datetime.now(timezone.utc) - timedelta(seconds=40)
    hdr = ("#fields\tts\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\n"
           "#types\ttime\taddr\tport\taddr\tport\tstring\n")
    rows = "".join(
        f"{(base + timedelta(seconds=i * 0.05)).timestamp():.6f}\t192.0.2.{i % 80 + 1}"
        f"\t4000\t10.0.0.4\t443\ttcp\n" for i in range(700))
    (tmp_path / "conn.log").write_text(hdr + rows)
    return d, store


@pytest.fixture()
def soar():
    _Soar.received = []
    srv = HTTPServer(("127.0.0.1", 0), _Soar)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield srv.server_address[1]
    srv.shutdown()


def test_critical_asset_ddos_needs_approval_then_reaches_the_soar(tmp_path, monkeypatch, soar):
    monkeypatch.setenv("SENTINEL_SOAR_TOKEN", "tok123")
    d, store = _flood_daemon(tmp_path, monkeypatch, level=1, dry_run=False, port=soar)
    d.run_once()
    dec = store.rows("decisions")[0]
    assert dec["outcome"] == "human_approval"            # 0.78 => human band
    assert _Soar.received == []                          # nothing before approval
    pending = d._engine.pending_approvals()
    assert list(pending) == [dec["incident_id"]]
    d._resolutions.put((dec["incident_id"], True))       # the Telegram path
    d.run_once()
    payload, auth = _Soar.received[0]
    assert payload["action"] == "recommend_upstream_mitigation"
    assert payload["target_ip"] == "10.0.0.4" and payload["ttl_minutes"] == 30
    assert auth == "Bearer tok123"
    act = store.rows("actions")[0]
    assert (act["verdict"], act["executed"]) == ("executed", 1)
    assert act["case_id"] == "telegram" and act["detail"].startswith("approved:")
    assert store.verify_chain()["ok"]
    store.close()


def test_default_dry_run_never_reaches_the_soar(tmp_path, monkeypatch, soar):
    d, store = _flood_daemon(tmp_path, monkeypatch, level=1, dry_run=True, port=soar)
    d.run_once()
    d._resolutions.put((store.rows("decisions")[0]["incident_id"], True))
    d.run_once()
    assert _Soar.received == []
    assert [r["verdict"] for r in store.rows("actions")] == ["dry_run"]
    store.close()


def test_level_zero_blocks_even_live_mode(tmp_path, monkeypatch, soar):
    d, store = _flood_daemon(tmp_path, monkeypatch, level=0, dry_run=False, port=soar)
    d.run_once()
    d._resolutions.put((store.rows("decisions")[0]["incident_id"], True))
    d.run_once()
    assert _Soar.received == []
    assert [r["verdict"] for r in store.rows("actions")] == ["withheld_autonomy"]
    store.close()


def test_ui_approval_route_triggers_the_executor(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient
    from sentinel.ui.app import create_app
    monkeypatch.setenv("TOK_UI_EXEC", "s3")
    eng, _, d = decision_for("auth_fail_burst", 0.93)
    store = Store(tmp_path / "a.sqlite", check_same_thread=False)
    seen = []
    app = create_app(
        {"ops_ui": {"enabled": True, "bind": "127.0.0.1:8080",
                    "auth_token_env": "TOK_UI_EXEC", "allowed_ports": [8080]}},
        engine=eng, store=store, on_resolved=seen.append)
    r = TestClient(app).post(f"/approvals/{d.incident_id}/approve",
                             headers={"X-Sentinel-Token": "s3"})
    assert r.status_code == 200 and len(seen) == 1
    assert seen[0].outcome.value == "auto_act"
    store.close()


def test_cli_refuses_live_mode_at_autonomy_zero(tmp_path, capsys):
    cfg = yaml.safe_load(CFG.read_text())
    cfg["audit_store"] = {"path": str(tmp_path / "a.sqlite")}
    cp = tmp_path / "c.yaml"
    cp.write_text(yaml.safe_dump(cfg))
    assert main(["--no-dry-run", "--config", str(cp), "run",
                 "--capture-dir", str(tmp_path)]) == 1
    assert "autonomy_level is 0" in capsys.readouterr().err


def test_ctl_rollback_all_is_honest_without_nft(monkeypatch, capsys):
    monkeypatch.setattr("shutil.which", lambda _: None)
    monkeypatch.setattr("subprocess.run",
                        lambda *a, **k: (_ for _ in ()).throw(FileNotFoundError("nft")))
    assert main(["ctl", "rollback", "--all"]) == 1
    assert "FAILED" in capsys.readouterr().out
