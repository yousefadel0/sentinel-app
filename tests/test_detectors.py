"""Phase 3 — behavioral detectors + evaluation-harness regression gate."""
from __future__ import annotations

import random
from datetime import datetime, timedelta, timezone

import pytest

from sentinel.detectors import DetectorConfig, DetectorSuite
from sentinel.detectors.dns import SUSPICIOUS_DNS, dns_signals
from sentinel.detectors.suite import is_incident_worthy
from sentinel.evaluation import harness as H

T0 = datetime(2026, 1, 15, 9, 0, 0, tzinfo=timezone.utc)


def _flow(rng, t, src, dst, dport):
    return H._alert(t, src, dst, dport, rng=rng)


def _run(events, cfg=None):
    return H.run_scenario(H.Scenario("t", None, events), cfg)


def test_dns_signals_flags_encoded_names_not_ordinary_ones():
    rng = random.Random(1)
    assert dns_signals(H._tunnel_name(rng)) == (SUSPICIOUS_DNS,)
    for name in H._BENIGN_NAMES + ("", None):
        assert dns_signals(name) == ()


def test_scan_requires_fast_fanout_not_slow_browsing():
    rng = random.Random(2)
    fast = [_flow(rng, i * 0.5, "203.0.113.9", f"10.0.0.{i + 1}", 445)
            for i in range(30)]
    slow = [_flow(rng, i * 20.0, "10.0.1.5", f"172.16.0.{i + 1}", 443)
            for i in range(30)]
    out = _run(fast + slow)
    assert [a.src_ip for a in out if a.signals == ("scan",)] == ["203.0.113.9"]


def test_brute_force_needs_auth_port_and_volume():
    rng = random.Random(3)
    ev = [_flow(rng, i * 2.0, "198.51.100.5", "10.0.0.4", 22) for i in range(20)]
    ev += [_flow(rng, i * 2.0, "198.51.100.6", "10.0.0.4", 8080) for i in range(20)]
    out = _run(ev)
    assert [a.src_ip for a in out] == ["198.51.100.5"]
    assert out[0].signals == ("auth_fail_burst",)


def test_beacon_ignores_ntp_and_jittery_polling():
    rng = random.Random(4)
    ntp = [_flow(rng, i * 64.0, "10.0.1.1", "1.1.1.1", 123) for i in range(30)]
    t, jitter = 0.0, []
    for _ in range(30):
        jitter.append(_flow(rng, t, "10.0.1.2", "8.8.4.4", 443))
        t += rng.uniform(30, 90)
    regular, t = [], 0.0
    for _ in range(20):
        regular.append(_flow(rng, t, "10.0.1.3", "185.1.1.1", 443))
        t += 60.0 * (1 + rng.uniform(-0.05, 0.05))
    out = _run(ntp + jitter + regular)
    assert [a.src_ip for a in out] == ["10.0.1.3"]
    assert out[0].signals == ("beacon_periodic",)


def test_detector_alerts_are_tier_b_and_correlatable():
    rng = random.Random(5)
    sc = H.brute(rng)
    out = H.run_scenario(sc)
    assert out and out[0].confidence_tier.value == "B"
    assert is_incident_worthy(out[0])
    assert not is_incident_worthy(sc.events[0])       # raw flow is not


def test_story_reemitted_only_on_doubling():
    rng = random.Random(6)
    suite = DetectorSuite(DetectorConfig(brute_min_conns=5))
    emitted = []
    for i in range(40):
        suite.ingest([_flow(rng, i * 1.0, "198.51.100.9", "10.0.0.4", 22)])
        emitted += suite.detect()
    counts = len(emitted)
    assert 2 <= counts <= 5            # 5,10,20,40 style — not one per event


def test_detect_is_quiet_without_new_events():
    suite = DetectorSuite()
    assert suite.detect() == []


def test_daemon_turns_conn_rows_into_scan_decision(tmp_path):
    import yaml
    from pathlib import Path
    from sentinel.auditstore.store import Store
    from sentinel.config.loader import load_config
    from sentinel.daemon import build_daemon

    cfg = yaml.safe_load(
        (Path(__file__).parent / "fixtures/valid_config.yaml").read_text())
    cfg["audit_store"] = {"path": str(tmp_path / "a.sqlite")}
    cp = tmp_path / "c.yaml"
    cp.write_text(yaml.safe_dump(cfg))
    store = Store(tmp_path / "a.sqlite")
    d = build_daemon(load_config(cp), tmp_path, store)
    base = datetime.now(timezone.utc) - timedelta(seconds=30)
    hdr = ("#fields\tts\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\n"
           "#types\ttime\taddr\tport\taddr\tport\tstring\n")
    rows = "".join(
        f"{(base + timedelta(seconds=i * 0.2)).timestamp():.6f}\t203.0.113.50\t4000\t"
        f"10.0.0.{i + 1}\t445\ttcp\n" for i in range(40))
    (tmp_path / "conn.log").write_text(hdr + rows)
    assert d.run_once() >= 1
    row = store.rows("decisions")[0]
    assert row["case_id"] == "live" and row["tier"] in ("A", "B")
    # ordinary conn rows alone never create incidents
    assert len(store.rows("decisions")) == d.decisions
    store.close()


@pytest.mark.slow
def test_evaluation_gate_recall_and_zero_benign_fp():
    rep = H.evaluate(range(2))
    for fam, m in rep.per_family.items():
        assert m["recall"] == 1.0, fam
        assert m["false_positives"] == 0, fam
    assert rep.benign_false_positives == 0


def test_critical_asset_target_reaches_the_action_band(tmp_path):
    """Regression for the 0.405 ceiling: configured critical assets must be
    known to the engine, so a DDoS on one lands in human approval (>=0.70)
    instead of log_only; the same flood on an ordinary host stays below."""
    import yaml
    from pathlib import Path
    from sentinel.auditstore.store import Store
    from sentinel.config.loader import load_config
    from sentinel.daemon import build_daemon

    cfg = yaml.safe_load(
        (Path(__file__).parent / "fixtures/valid_config.yaml").read_text())
    cfg["audit_store"] = {"path": str(tmp_path / "a.sqlite")}
    cp = tmp_path / "c.yaml"
    cp.write_text(yaml.safe_dump(cfg))
    store = Store(tmp_path / "a.sqlite")
    d = build_daemon(load_config(cp), tmp_path, store)
    base = datetime.now(timezone.utc) - timedelta(seconds=40)
    hdr = ("#fields\tts\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\n"
           "#types\ttime\taddr\tport\taddr\tport\tstring\n")
    rows = []
    for victim in ("10.0.0.4", "10.0.9.9"):             # critical vs ordinary
        for i in range(700):
            t = (base + timedelta(seconds=i * 0.05)).timestamp()
            rows.append(f"{t:.6f}\t192.0.2.{i % 80 + 1}\t4000\t{victim}\t443\ttcp\n")
    (tmp_path / "conn.log").write_text(hdr + "".join(rows))
    d.run_once()
    by_dst = {}
    for r in store.rows("incident_context"):
        by_dst[r["dst_ip"]] = r["incident_id"]
    outcome = {r["incident_id"]: (r["outcome"], r["score"])
               for r in store.rows("decisions")}
    crit = outcome[by_dst["10.0.0.4"]]
    ordinary = outcome[by_dst["10.0.9.9"]]
    assert crit[0] == "human_approval" and crit[1] >= 0.70
    assert ordinary[0] == "log_only" and ordinary[1] < 0.70
    store.close()
