"""Autonomy ladder L0–L3: manual-only upgrades, KPI-driven downgrades via
synthetic inputs (D4), SOC alert JSON lines (Q6).
"""
from __future__ import annotations

import logging

import pytest

from sentinel.decision.autonomy import (
    AutonomyController,
    CIRCUIT_BREAKER_ROLLBACKS,
    FP_DOWNGRADE_THRESHOLD,
    FP_SEVERE_THRESHOLD,
)


# --------------------------------------------------------------------- #
# ladder basics — manual only
# --------------------------------------------------------------------- #
def test_default_level_is_zero_and_bounds_enforced():
    assert AutonomyController().level == 0
    with pytest.raises(ValueError):
        AutonomyController(level=4)
    with pytest.raises(ValueError):
        AutonomyController(level=-1)


def test_manual_upgrade_one_step_at_a_time_with_evidence():
    ctl = AutonomyController(level=0)
    ctl.upgrade_manual(1, kpi_evidence="14d FP rate 2.1%")
    assert ctl.level == 1
    ctl.upgrade_manual(2, kpi_evidence="14d FP rate 1.7%")
    assert ctl.level == 2


def test_upgrade_refuses_jumps_and_missing_evidence():
    ctl = AutonomyController(level=0)
    with pytest.raises(ValueError, match="one step"):
        ctl.upgrade_manual(2, kpi_evidence="skipping L1")
    with pytest.raises(ValueError, match="KPI evidence"):
        ctl.upgrade_manual(1, kpi_evidence="")
    with pytest.raises(ValueError, match="one step"):
        ctl.upgrade_manual(4, kpi_evidence="beyond L3")


def test_no_automatic_upgrade_path_exists():
    """The ONLY mutators are upgrade_manual and apply_kpi_signal (downgrades).
    Binding 6: ladder moves up exclusively by operator hand."""
    mutators = {m for m in dir(AutonomyController) if not m.startswith("_")}
    assert mutators == {"level", "upgrade_manual", "apply_kpi_signal"}


# --------------------------------------------------------------------- #
# KPI downgrades — explicit inputs only (D4)
# --------------------------------------------------------------------- #
def test_fp_rate_above_5_downgrades_one_level():
    ctl = AutonomyController(level=2)
    ctl.apply_kpi_signal(fp_rate_14d=FP_DOWNGRADE_THRESHOLD + 0.1)
    assert ctl.level == 1


def test_fp_rate_at_exactly_5_is_not_a_breach():
    ctl = AutonomyController(level=2)
    ctl.apply_kpi_signal(fp_rate_14d=5.0)
    assert ctl.level == 2


def test_fp_rate_above_8_downgrades_two_levels_with_soc_alert(caplog):
    caplog.set_level("ERROR", logger="sentinel.decision.autonomy")
    ctl = AutonomyController(level=2)
    ctl.apply_kpi_signal(fp_rate_14d=FP_SEVERE_THRESHOLD + 0.1)
    assert ctl.level == 0
    alerts = [r for r in caplog.records
              if r.__dict__.get("reason") == "fp_rate_breach"]
    assert alerts, "expected an immediate SOC alert line (Q6)"
    rec = alerts[0]
    assert rec.getMessage() == "soc_alert"          # event name verbatim
    assert rec.levelno >= logging.ERROR             # alarm severity
    assert rec.__dict__["level_changed"] is True
    assert rec.__dict__["fp_rate_14d"] == FP_SEVERE_THRESHOLD + 0.1


def test_circuit_breaker_three_consecutive_rollbacks_downgrades_one():
    assert CIRCUIT_BREAKER_ROLLBACKS == 3
    ctl = AutonomyController(level=1)
    ctl.apply_kpi_signal(consecutive_rollbacks=3)
    assert ctl.level == 0


def test_floor_at_l0_held_for_all_downgrade_paths():
    ctl = AutonomyController(level=0)
    ctl.apply_kpi_signal(fp_rate_14d=99.0)          # would be −2
    assert ctl.level == 0
    ctl.apply_kpi_signal(consecutive_rollbacks=10)  # would be −1
    assert ctl.level == 0


def test_combined_signals_apply_in_order_fp_then_breaker():
    """FP 8.4% (−2 from L2 → L0) then breaker would stay at floor."""
    ctl = AutonomyController(level=2)
    ctl.apply_kpi_signal(fp_rate_14d=8.4, consecutive_rollbacks=3)
    assert ctl.level == 0


def test_none_inputs_are_no_ops():
    ctl = AutonomyController(level=3)
    ctl.apply_kpi_signal()
    assert ctl.level == 3
