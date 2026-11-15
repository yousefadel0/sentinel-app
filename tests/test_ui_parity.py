"""M7 watchpoint: byte-identical audit rows, CLI seam vs Ops UI route.

Both paths must resolve a pending approval through Engine.resolve and
record through Store.record_decision such that the resulting decisions
row is identical — under a shared injected clock and a frozen wall-clock
stamp — except case_id ("pilot" vs "ops_ui"), which legitimately names
the entry channel.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

FROZEN_TS = "2026-01-01T00:00:00Z"


def _pending(engine_factory):
    """Identically-seeded engine + one pending human_approval decision."""
    import tests.fixtures.decision.helpers as helpers
    from sentinel.decision.chain import Facts
    # Reset the module-level id sequence so both paths mint identical ids.
    helpers._SEQ = iter(range(1, 100000))
    FakeClock, IncidentStub, alert = (helpers.FakeClock,
                                      helpers.IncidentStub, helpers.alert)
    eng, clk = engine_factory(clock=FakeClock())
    d = eng.evaluate(IncidentStub([alert("auth_fail_burst", 0.93,
                                         crit="critical")]),
                     Facts(liveness="alive"))
    assert d.outcome.value == "human_approval"
    return eng, clk, d


def _cli_record(store, decision) -> None:
    """The pilot/CLI recording call (sentinel/pilot/runner.py verbatim)."""
    from dataclasses import asdict
    rec = decision.recommendation
    store.record_decision(
        case_id="pilot",
        incident_id=decision.incident_id,
        outcome=decision.outcome.value,
        score=float(decision.score),
        base_score=float(decision.base_score),
        tier=decision.tier,
        cap_applied=decision.cap_applied,
        would=decision.would,
        recommendation=(asdict(rec) if rec is not None else {}),
        audit_events=[asdict(e) for e in decision.audit_events],
    )


@pytest.fixture()
def frozen_now(monkeypatch):
    from sentinel.auditstore import store as store_mod
    monkeypatch.setattr(store_mod, "_utc_now_iso", lambda: FROZEN_TS)


def test_ui_route_row_matches_cli_seam_row(frozen_now, monkeypatch,
                                           tmp_path):
    monkeypatch.setenv("SENTINEL_TEST_OPS_UI_TOKEN", "s3cret")
    from tests.fixtures.decision.helpers import engine as engine_factory
    from sentinel.auditstore.store import Store

    # -- path A: CLI seam ------------------------------------------------ #
    eng_a, _, d_a = _pending(engine_factory)
    db_a = tmp_path / "cli.sqlite"
    store_a = Store(db_a)
    resolved_a = eng_a.resolve(d_a.incident_id, True,
                               actor="ops_ui_authenticated")
    _cli_record(store_a, resolved_a)

    # -- path B: Ops UI route ------------------------------------------- #
    eng_b, _, d_b = _pending(engine_factory)
    db_b = tmp_path / "ui.sqlite"
    store_b = Store(db_b, check_same_thread=False)
    from fastapi.testclient import TestClient
    from sentinel.ui.app import create_app
    app = create_app({"ops_ui": {"enabled": True,
                                 "bind": "127.0.0.1:8080",
                                 "auth_token_env": "SENTINEL_TEST_OPS_UI_TOKEN",
                                 "allowed_ports": [8080]}},
                     engine=eng_b, store=store_b)
    c = TestClient(app)
    r = c.post(f"/approvals/{d_b.incident_id}/approve",
               headers={"X-Sentinel-Token": "s3cret"})
    assert r.status_code == 200

    # -- compare rows ----------------------------------------------------- #
    row_cli = store_a.rows("decisions")[0]
    row_ui = store_b.rows("decisions")[0]
    for col in ("ts", "incident_id", "outcome", "score", "base_score",
                "tier", "cap_applied", "would", "recommendation",
                "audit_events"):
        assert row_cli[col] == row_ui[col], f"column {col!r} diverges"
    assert row_cli["case_id"] != row_ui["case_id"]
    assert {row_cli["case_id"], row_ui["case_id"]} == {"pilot", "ops_ui"}
