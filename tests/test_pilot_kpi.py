"""M6 KPI pipeline — D4 semantics and the Q1 two-name pin."""
from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sentinel.auditstore.store import Store  # noqa: E402
from sentinel.pilot.kpi import compute_kpis  # noqa: E402


def _fresh_store() -> Store:
    return Store(Path(tempfile.mkdtemp()) / "audit.sqlite")


def test_empty_store_honest_zeros():
    k = compute_kpis(_fresh_store())
    assert k["incidents"] == 0
    assert k["mttd_seconds"] == {"n": 0, "avg": None}
    assert k["mttd_replay_seconds"] == {"n": 0, "avg": None}
    assert k["fp_rate"] == {"flagged": 0, "benign_injections": 0}
    assert k["llm_latency_ms"]["p50"] is None


def test_mttd_names_never_blended_q1():
    s = _fresh_store()
    for path in ("generator", "replay"):
        s.record_kpi_event(case_id="c-1", name="mttd", value=10.0,
                           detail=json.dumps({"path": path}))
    k = compute_kpis(s)
    assert k["mttd_seconds"] == {"n": 1, "avg": 10.0}
    assert k["mttd_replay_seconds"] == {"n": 1, "avg": 10.0}


def test_fp_rate_counts_only_benign_and_reports_n_m():
    s = _fresh_store()
    s.record_kpi_event(case_id="b1", name="fp_event", value=1,
                       detail=json.dumps({"benign": True, "flagged": False}))
    s.record_kpi_event(case_id="b2", name="fp_event", value=1,
                       detail=json.dumps({"benign": True, "flagged": True}))
    s.record_kpi_event(case_id="a1", name="fp_event", value=1,
                       detail=json.dumps({"benign": False, "flagged": True}))
    k = compute_kpis(s)
    # n/m shape: flagged benign over total benign injections; attack row ignored.
    assert k["fp_rate"] == {"flagged": 1, "benign_injections": 2}


def test_actions_rollbacks_llm_latency():
    s = _fresh_store()
    s.record_action(case_id="c-1", action_type="throttle", target_ip=None,
                    ttl_minutes=None, verdict="auto_throttle", executed=True)
    s.record_action(case_id="c-2", action_type="block", target_ip=None,
                    ttl_minutes=None, verdict="escalate_human", executed=False)
    s.record_rollback(case_id="c-1", token="t1", ok=True)
    for ms in (100, 200):
        s.record_llm_pair(case_id="c-x", prompt_verbatim="p",
                          response_verbatim="r", status="ok",
                          elapsed_ms=ms, digest=f"d{ms}")
    s.record_llm_pair(case_id="c-y", prompt_verbatim="p",
                      response_verbatim="r", status="error",
                      elapsed_ms=9999, digest="dz")
    k = compute_kpis(s)
    assert k["actions_recorded"] == 2
    assert k["actions_executed"] == 1
    assert k["rollbacks"] == 1
    assert k["llm_pairs"] == 3
    # p50 over OK pairs only: median of {100, 200} -> 150 with _avg rounding.
    assert k["llm_latency_ms"]["n"] == 2
    assert k["llm_latency_ms"]["p50"] == 150.0


def test_decisions_by_outcome_tally():
    s = _fresh_store()
    rec = dict(case_id="c-1", incident_id="i-1", outcome="auto_throttle",
               score=0.9, base_score=0.8, tier="A", cap_applied=None,
               would="throttle", recommendation={}, audit_events=[])
    for _ in range(3):
        s.record_decision(**rec)
    s.record_decision(**{**rec, "outcome": "log_only"})
    k = compute_kpis(s)
    assert k["incidents"] == 4
    assert k["decisions_by_outcome"] == {"auto_throttle": 3, "log_only": 1}
