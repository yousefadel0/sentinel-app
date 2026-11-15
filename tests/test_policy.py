"""P1 — thresholds from config, per-asset criticality, G1 on the action target."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
import yaml

from sentinel.config.loader import ConfigError, load_config
from sentinel.decision import AutonomyController, DecisionEngine, RateLimiter
from sentinel.decision.chain import Facts
from sentinel.pilot.runner import _config_view, asset_hints
from tests.fixtures.decision.helpers import (FakeClock, IncidentStub, alert,
                                              config_view)

CFG = Path(__file__).parent / "fixtures" / "valid_config.yaml"


class Inc(IncidentStub):
    def __init__(self, alerts, src="198.51.100.7", dst="10.0.0.99"):
        super().__init__(alerts, dst_ip=dst)
        if src:
            self.src_ip = src


def eng(**cv):
    return DecisionEngine(config_view=config_view(**cv), clock=FakeClock(),
                          rate_limiter=RateLimiter(5, 20),
                          controller=AutonomyController(0))


def run(engine, signal, conf, crit, **kw):
    return engine.evaluate(Inc([alert(signal, conf, crit=crit,
                                      dst=kw.get("dst", "10.0.0.99"))], **kw),
                           Facts(liveness="alive"))


# -- thresholds ------------------------------------------------------------------

def test_threshold_decides_auto_vs_human():
    d90 = run(eng(auto_threshold=0.90), "volume_spike", 0.92, "critical")
    d95 = run(eng(auto_threshold=0.95), "volume_spike", 0.92, "critical")
    assert d90.outcome.value == "auto_act" and d95.outcome.value == "human_approval"
    low = run(eng(human_threshold=0.80), "auth_fail_burst", 0.93, "critical")
    assert low.outcome.value == "human_approval"


def test_config_defaults_are_95_80_and_50(tmp_path):
    cfg = yaml.safe_load(CFG.read_text())
    view = _config_view(cfg)
    assert (view.auto_threshold, view.human_threshold, view.report_threshold) == (0.95, 0.80, 0.50)
    cfg["policy"] = {"auto_act_threshold": 0.97, "human_approval_threshold": 0.6}
    view = _config_view(load_config(_write(tmp_path, cfg)))
    assert (view.auto_threshold, view.human_threshold) == (0.97, 0.6)


def _write(tmp_path, cfg):
    p = tmp_path / "c.yaml"
    p.write_text(yaml.safe_dump(cfg))
    return p


def test_invalid_policy_is_refused(tmp_path):
    cfg = yaml.safe_load(CFG.read_text())
    cfg["policy"] = {"auto_act_threshold": 0.8, "human_approval_threshold": 0.9}
    with pytest.raises(ConfigError, match="approval threshold"):
        load_config(_write(tmp_path, cfg))
    cfg["policy"] = {"auto_act_threshold": 0.3}
    with pytest.raises(ConfigError):
        load_config(_write(tmp_path, cfg))


# -- G1 judges the action target ---------------------------------------------------

def test_blocking_an_outside_attacker_of_a_critical_server_reaches_a_human():
    e = eng(critical_assets=frozenset({"10.0.0.4"}))
    d = run(e, "auth_fail_burst", 0.97, "critical", src="198.51.100.7", dst="10.0.0.4")
    assert d.outcome.value == "auto_act"
    assert d.recommendation.action == "block_ip_temp"
    assert not any(ev.name == "critical_asset_allowlist_hit" for ev in d.audit_events)


def test_g1_still_blocks_when_the_target_itself_is_critical():
    e = eng(critical_assets=frozenset({"10.0.0.4", "198.51.100.7"}))
    d = run(e, "auth_fail_burst", 0.97, "critical", src="198.51.100.7", dst="10.0.0.99")
    assert d.outcome.value == "escalate_human"
    assert any(ev.name == "critical_asset_allowlist_hit" for ev in d.audit_events)


def test_protected_admin_ip_caps_the_decision_before_execution():
    e = eng(protected_ips=frozenset({"198.51.100.7"}))
    d = run(e, "auth_fail_burst", 0.98, "critical", src="198.51.100.7")
    assert d.outcome.value == "escalate_human"
    assert any(ev.name == "critical_asset_allowlist_hit" for ev in d.audit_events)


def test_g1_falls_back_to_dst_when_src_is_unknown():
    e = eng(critical_assets=frozenset({"10.0.0.4"}))
    d = run(e, "auth_fail_burst", 0.97, "critical", src=None, dst="10.0.0.4")
    assert d.outcome.value == "escalate_human"             # conservative legacy rule


def test_c2_quarantine_targets_dst_so_g1_checks_dst():
    e = eng(critical_assets=frozenset({"10.0.0.4"}))
    d = run(e, "beacon_periodic", 0.97, "critical", src="10.0.2.5", dst="10.0.0.4")
    assert d.outcome.value == "escalate_human"


# -- per-asset criticality ----------------------------------------------------------

def test_asset_hints_default_critical_and_inventory_overrides(tmp_path):
    cfg = yaml.safe_load(CFG.read_text())
    cfg["site"]["critical_assets"][1]["criticality"] = "high"
    cfg["site"]["assets"] = [
        {"ip": "10.0.5.5", "hostname": "web-01", "criticality": "high"},
        {"ip": "10.0.0.4", "hostname": "dup", "criticality": "low"}]
    hints = asset_hints(load_config(_write(tmp_path, cfg)))
    assert hints["10.0.0.4"].criticality == "critical"      # G1 member wins
    assert hints["10.0.0.5"].criticality == "high"
    assert hints["10.0.5.5"].criticality == "high"          # score-only, not G1
    assert "10.0.5.5" not in _config_view(cfg).critical_assets


def test_invalid_asset_criticality_is_refused(tmp_path):
    cfg = yaml.safe_load(CFG.read_text())
    cfg["site"]["assets"] = [{"ip": "10.0.5.5", "hostname": "w", "criticality": "ultra"}]
    with pytest.raises(ConfigError):
        load_config(_write(tmp_path, cfg))


# -- end to end through the daemon ----------------------------------------------------

def test_brute_force_confidence_drives_band_before_asset_score(tmp_path):
    from sentinel.auditstore.store import Store
    from sentinel.daemon import build_daemon
    cfg = yaml.safe_load(CFG.read_text())
    cfg["audit_store"] = {"path": str(tmp_path / "a.sqlite")}
    cp = _write(tmp_path, cfg)
    store = Store(tmp_path / "a.sqlite")
    d = build_daemon(load_config(cp), tmp_path, store,
                     liveness_check=lambda ctx: "alive")  # synthetic proof
    base = datetime.now(timezone.utc) - timedelta(seconds=60)
    hdr = ("#fields\tts\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\n"
           "#types\ttime\taddr\tport\taddr\tport\tstring\n")
    rows = "".join(
        f"{(base + timedelta(seconds=i * 1.5)).timestamp():.6f}\t198.51.100.77\t5000\t"
        f"10.0.0.4\t22\ttcp\n" for i in range(40))
    (tmp_path / "conn.log").write_text(hdr + rows)
    d.run_once()
    dec = store.rows("decisions")[0]
    assert dec["outcome"] == "auto_throttle" and 0.50 <= dec["score"] < 0.80
    assert not d._engine.pending_approvals()
    store.close()
