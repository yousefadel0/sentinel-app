"""Phase 5 — notifiers, chat approvals, SIEM inbound/outbound, config schema."""
from __future__ import annotations

import json
import socket
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
import yaml

from sentinel.auditstore.store import Store
from sentinel.config.loader import ConfigError, load_config
from sentinel.daemon import Daemon
from sentinel.decision.chain import Facts
from sentinel.notify import NotifierHub, TelegramSender, WebhookSender, build_notification
from sentinel.notify.approvals import TelegramApprovals
from sentinel.siem.inbound import WazuhAlertsFileDataSource
from sentinel.siem.outbound import SiemExporter, to_cef
from tests.fixtures.decision.helpers import FakeClock, IncidentStub, alert, engine

CFG = Path(__file__).parent / "fixtures" / "valid_config.yaml"


class Inc(IncidentStub):
    src_ip = "198.51.100.7"
    dst_ip = "10.0.0.4"


def _decision(signal="auth_fail_burst", conf=0.93, crit="critical"):
    eng, clk = engine(clock=FakeClock())
    inc = Inc([alert(signal, conf, crit=crit)])
    return eng, inc, eng.evaluate(inc, Facts(liveness="alive"))


class FakeSender:
    name = "fake"

    def __init__(self, ok=True):
        self.sent, self.ok = [], ok

    def send(self, n):
        self.sent.append(n)
        if not self.ok:
            raise RuntimeError("boom")
        return True


# -- notifications ----------------------------------------------------------

def test_notification_carries_approval_id_and_no_payload():
    _, inc, d = _decision()
    n = build_notification(d, inc)
    assert d.outcome.value == "human_approval"
    assert n.approval_id == d.incident_id and n.severity == "high"
    assert "198.51.100.7" in n.title


def test_hub_filters_dedupes_caps_and_survives_failures():
    _, inc, d = _decision()
    t = [0.0]
    s = FakeSender()
    hub = NotifierHub([s], clock=lambda: t[0], max_per_min=2, synchronous=True)
    assert hub.notify(d, inc) is True
    assert hub.notify(d, inc) is False                  # deduped
    t[0] = 700.0
    assert hub.notify(d, inc) is True                   # window passed
    inc2 = Inc([alert("auth_fail_burst", 0.93, crit="critical")])
    inc2.src_ip = "198.51.100.8"
    assert hub.notify(d, inc2) is True                  # 2nd within the minute
    inc3 = Inc([alert("auth_fail_burst", 0.93, crit="critical")])
    inc3.src_ip = "198.51.100.9"
    assert hub.notify(d, inc3) is False and hub.suppressed == 1   # cap (2/min)
    bad = NotifierHub([FakeSender(ok=False)], synchronous=True)
    assert bad.notify(d, inc) is True and bad.failures == 1       # no raise
    _, inc4, low = _decision("scan", 0.3, crit="low")
    assert hub.notify(low, inc4) is False                          # log_only


def test_webhook_formats_and_env_secret(monkeypatch):
    _, inc, d = _decision()
    n = build_notification(d, inc)
    calls = []
    tr = lambda url, body, timeout: calls.append((url, body)) or 200
    monkeypatch.delenv("HOOK", raising=False)
    assert WebhookSender("HOOK", "slack", transport=tr).send(n) is False
    monkeypatch.setenv("HOOK", "https://hooks.example/x")
    assert WebhookSender("HOOK", "slack", transport=tr).send(n) is True
    assert "text" in calls[0][1] and n.approval_id in calls[0][1]["text"]
    WebhookSender("HOOK", "generic", transport=tr).send(n)
    assert calls[1][1]["incident_id"] == d.incident_id
    with pytest.raises(ValueError):
        WebhookSender("HOOK", "pager")
    monkeypatch.setenv("TG", "123:abc")
    TelegramSender("TG", "42", transport=tr).send(n)
    assert calls[2][0] == "https://api.telegram.org/bot123:abc/sendMessage"
    assert calls[2][1]["chat_id"] == "42"


# -- chat approvals ---------------------------------------------------------

def _updates(*msgs):
    return {"result": [{"update_id": i + 10, "message": {
        "chat": {"id": chat}, "text": text}} for i, (chat, text) in enumerate(msgs)]}


def test_telegram_accepts_only_configured_chat_and_exact_commands(monkeypatch):
    monkeypatch.setenv("TG", "123:abc")
    seen = []
    api = _updates((42, "/approve inc-1"), (99, "/approve inc-2"),
                   (42, "/deny inc-3@bot"), (42, "approve inc-4"),
                   (42, "/approve inc-5; rm -rf /"), (42, "/deny  inc-6 "))
    ap = TelegramApprovals("TG", "42", fetch=lambda u, t: seen.append(u) or api)
    assert [r[:2] for r in ap.poll_once()] == [("inc-1", True), ("inc-6", False)]
    ap.poll_once()
    assert "offset=16" in seen[1]                         # acked, not replayed
    monkeypatch.delenv("TG")
    assert ap.poll_once() == []


def _daemon_with_engine(tmp_path, eng, **kw):
    store = Store(tmp_path / "a.sqlite")
    return Daemon(sources=[], engine=eng, store=store, **kw), store


def test_chat_approval_goes_through_engine_resolve_and_audit(tmp_path):
    eng, inc, d = _decision()
    d2, store = _daemon_with_engine(tmp_path, eng)
    assert d.incident_id in eng.pending_approvals()
    d2._resolutions.put((d.incident_id, True))
    d2._resolutions.put(("nope", True))                   # stale id is harmless
    d2.run_once()
    row = store.rows("decisions")[0]
    assert row["case_id"] == "telegram" and row["outcome"] == "auto_act"
    assert "human_approval_granted" in row["audit_events"]
    assert eng.pending_approvals() == {}
    store.close()


# -- SIEM outbound ----------------------------------------------------------

def _seed(store, n=3):
    for i in range(n):
        store.record_decision(
            case_id="live", incident_id=f"inc-{i}", outcome="notify_only",
            score=0.5, base_score=0.5, tier="A", cap_applied=None,
            would="evil=| \n inj", recommendation={}, audit_events=[])


def test_cef_escapes_delimiters_and_newlines():
    line = to_cef({"incident_id": "i", "outcome": "a|b", "tier": "A",
                   "score": 0.5, "would": "x=y\nz", "ts": "t", "case_id": "c"})
    assert line.startswith("CEF:0|Sentinel|Sentinel|1|a\\|b|")
    assert "\n" not in line and "msg=x\\=y z" in line


def test_exporter_high_water_mark_and_outage_retry(tmp_path):
    store = Store(tmp_path / "a.sqlite")
    _seed(store, 3)
    batches, fail = [], [True]

    def sender(rows):
        if fail[0]:
            raise OSError("siem down")
        batches.append([r["id"] for r in rows])

    ex = SiemExporter(store, "syslog+udp://127.0.0.1:514",
                      tmp_path / "s.json", batch_size=2, sender=sender)
    assert ex.run_once() == 0                             # outage: nothing lost
    fail[0] = False
    assert ex.run_once() == 2 and ex.run_once() == 1 and ex.run_once() == 0
    assert batches == [[1, 2], [3]]
    ex2 = SiemExporter(store, "https://siem.example/in", tmp_path / "s.json",
                       sender=sender)                      # restart: no re-send
    assert ex2.run_once() == 0
    with pytest.raises(ValueError):
        SiemExporter(store, "http://plain.example", tmp_path / "x.json")
    store.close()


def test_exporter_real_udp_syslog(tmp_path):
    store = Store(tmp_path / "a.sqlite")
    _seed(store, 1)
    srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    srv.bind(("127.0.0.1", 0))
    srv.settimeout(3)
    ex = SiemExporter(store, f"syslog+udp://127.0.0.1:{srv.getsockname()[1]}",
                      tmp_path / "s.json")
    assert ex.run_once() == 1
    assert srv.recv(4096).decode().startswith("CEF:0|Sentinel|")
    srv.close()
    store.close()


# -- SIEM inbound (Tier C) --------------------------------------------------

def _wazuh(groups, srcip="203.0.113.9", agent="10.0.0.4"):
    return json.dumps({"timestamp": "2026-10-20T08:00:01.000+0000",
                       "rule": {"groups": groups},
                       "agent": {"ip": agent}, "data": {"srcip": srcip}}) + "\n"


def test_wazuh_source_emits_tier_c_auth_failures_only(tmp_path):
    f = tmp_path / "alerts.json"
    f.write_text(_wazuh(["syslog", "sshd", "authentication_failed"])
                 + _wazuh(["syslog", "systemd"])
                 + _wazuh(["authentication_failed"], srcip="not-an-ip")
                 + "garbage\n")
    src = WazuhAlertsFileDataSource(f)
    alerts = src.fetch()
    assert len(alerts) == 1
    a = alerts[0]
    assert a.confidence_tier.value == "C" and a.signals == ("auth_fail_burst",)
    assert (a.src_ip, a.dst_ip) == ("203.0.113.9", "10.0.0.4")
    assert src.health()["malformed_lines_skipped"] == 2
    assert src.fetch() == []


def test_siem_evidence_alone_never_auto_acts(tmp_path):
    f = tmp_path / "alerts.json"
    f.write_text(_wazuh(["authentication_failed"]) * 30)
    eng, _ = engine(clock=FakeClock(datetime(2026, 10, 20, 8, 1,
                                              tzinfo=timezone.utc)))
    d, store = _daemon_with_engine(
        tmp_path, eng, clock=lambda: datetime(2026, 10, 20, 8, 1,
                                              tzinfo=timezone.utc))
    d._sources = [WazuhAlertsFileDataSource(f)]
    assert d.run_once() >= 1
    for row in store.rows("decisions"):
        assert row["tier"] == "C"
        assert row["outcome"] not in ("auto_act", "auto_throttle")
    store.close()


# -- config schema ----------------------------------------------------------

def _cfg(tmp_path, **extra):
    cfg = yaml.safe_load(CFG.read_text())
    cfg.update(extra)
    p = tmp_path / "c.yaml"
    p.write_text(yaml.safe_dump(cfg))
    return p


def test_notifiers_block_validated(tmp_path):
    ok = [{"type": "webhook", "url_env": "SLACK_URL", "format": "slack"},
          {"type": "telegram", "url_env": "TG_TOKEN", "chat_id": "42",
           "approvals": True}]
    assert load_config(_cfg(tmp_path, notifiers=ok))["notifiers"] == ok
    for bad in ([{"type": "telegram", "url_env": "T"}],            # no chat_id
                [{"type": "carrier_pigeon", "url_env": "X"}],
                [{"type": "webhook", "url_env": "X", "url": "https://leak"}]):
        with pytest.raises(ConfigError):
            load_config(_cfg(tmp_path, notifiers=bad))
