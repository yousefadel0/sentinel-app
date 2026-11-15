"""Learning state survives restart and gates every enforcement route."""
from datetime import datetime, timedelta, timezone
from dataclasses import replace
import json

import pytest

from sentinel.learning import LearningProfile
from sentinel.cli import main
from tests.fixtures.decision.helpers import alert
from tests.test_executor import CTX, decision_for, make


def test_profile_persists_features_and_switches_on_day_fourteen(tmp_path):
    now = [datetime(2026, 4, 1, 12, tzinfo=timezone.utc)]
    path = tmp_path / "learning.json"
    profile = LearningProfile(path, clock=lambda: now[0])
    sample = alert("auth_fail_burst", 0.9)
    for day in range(14):
        now[0] = datetime(2026, 4, 1 + day, 12, tzinfo=timezone.utc)
        profile.observe([replace(sample, ts=now[0].isoformat())])
    report = profile.export()
    assert report["mode"] == "learning"
    assert report["features"]["ports"]["22"] == 14
    assert report["features"]["protocols"]["tcp"] == 14
    assert report["features"]["auth"]["auth"] == 14
    now[0] = datetime(2026, 4, 15, 12, tzinfo=timezone.utc)
    restored = LearningProfile(path, clock=lambda: now[0])
    assert restored.mode == "active"
    assert restored.export()["features"]["hosts"]["203.0.113.7"] == 14


def test_elapsed_time_without_fourteen_observed_days_stays_in_learning(tmp_path):
    now = [datetime(2026, 4, 1, 12, tzinfo=timezone.utc)]
    profile = LearningProfile(tmp_path / "learning.json", clock=lambda: now[0])
    profile.observe([replace(alert("zeek_conn", 0.5), ts=now[0].isoformat())])
    now[0] += timedelta(days=14)
    assert profile.mode == "learning"


def test_corrupt_learning_profile_refuses_startup(tmp_path):
    path = tmp_path / "learning.json"
    path.write_text(json.dumps({"version": 1, "days": {}}))
    with pytest.raises(ValueError, match="invalid learning profile"):
        LearningProfile(path)


def test_extend_and_manual_override_survive_restart(tmp_path):
    now = [datetime(2026, 4, 1, 12, tzinfo=timezone.utc)]
    path = tmp_path / "learning.json"
    profile = LearningProfile(path, clock=lambda: now[0])
    profile.extend(7)
    now[0] += timedelta(days=15)
    assert LearningProfile(path, clock=lambda: now[0]).mode == "learning"
    profile.set_override("active")
    assert LearningProfile(path, clock=lambda: now[0]).mode == "active"
    profile.set_override("learning")
    assert LearningProfile(path, clock=lambda: now[0]).mode == "learning"


def test_operator_control_is_visible_to_running_profile(tmp_path, capsys):
    path = tmp_path / "learning.json"
    running = LearningProfile(path)
    assert main(["ctl", "learning", str(path), "mode", "active"]) == 0
    capsys.readouterr()
    assert running.mode == "active"
    assert main(["ctl", "learning", str(path), "extend", "2"]) == 0
    assert running.export()["active_at"]


def test_learning_mode_withholds_even_with_high_score_and_live_proof(tmp_path):
    _, _, decision = decision_for("volume_spike", 1.0)
    state = [False]
    ex, store, acts, _ = make(tmp_path, can_act=lambda: state[0])
    assert ex.handle(decision, CTX, "auto") == "withheld_autonomy"
    assert not acts["webhook_soar"].calls
    state[0] = True
    assert ex.handle(decision, CTX, "auto") == "executed"
    store.close()


def test_active_profile_detects_new_service_without_block_authority(tmp_path):
    start = datetime(2026, 4, 1, 12, tzinfo=timezone.utc)
    now = [start]
    profile = LearningProfile(tmp_path / "learning.json", clock=lambda: now[0])
    for day in range(14):
        now[0] = start + timedelta(days=day)
        sample = replace(alert("zeek_conn", 0.5), ts=now[0].isoformat())
        profile.observe([sample])
    now[0] = start + timedelta(days=14)
    novel = replace(sample, ts=now[0].isoformat(), dst_port=8443)
    results = profile.anomalies([novel])
    assert profile.mode == "active" and len(results) == 1
    assert results[0].signals == ("baseline_anomaly",)
    assert results[0].confidence_tier.value == "B"
    assert profile.anomalies([replace(novel, dst_port=22)]) == []
    before = profile.export()["features"]
    profile.observe([novel])
    assert profile.export()["features"] == before
