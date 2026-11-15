"""Scoring arithmetic + CALIBRATION table (Q1 binding).

Proves the named constants put canonical attacks in documented bands and
that §3.1 penalties land BEFORE banding (D1).
"""
from __future__ import annotations

import pytest

from sentinel.decision.scoring import (
    CRITICALITY_WEIGHTS,
    PENALTY_BLIND_SPOT_VLAN,
    PENALTY_NAT_FALLBACK,
    SEVERITY_DEFAULTS,
    apply_penalties,
    band,
    base_score,
)


# --------------------------------------------------------------------- #
# constant tables are exactly what the operator approved
# --------------------------------------------------------------------- #
def test_criticality_weights_table_exact():
    assert CRITICALITY_WEIGHTS == {
        "critical": 1.0, "high": 0.85, "medium": 0.65, "low": 0.45,
    }


def test_severity_defaults_table_exact():
    assert SEVERITY_DEFAULTS == {
        "scan": 2, "brute_force": 4, "ddos_volumetric": 5,
        "c2_beacon": 4, "dns_tunneling": 3,
        "baseline_anomaly": 5,
    }


def test_penalty_constants_verbatim():
    assert PENALTY_NAT_FALLBACK == -0.15
    assert PENALTY_BLIND_SPOT_VLAN == -0.20


# --------------------------------------------------------------------- #
# arithmetic + input validation
# --------------------------------------------------------------------- #
@pytest.mark.parametrize("conf,crit,sev,expected", [
    (0.93, "critical", 4, 0.744),   # calibration row: brute force vs dc-01
    (1.0, "critical", 5, 1.0),      # full-confidence volumetric DoS
    (0.9, "medium", 4, 0.468),      # c2 beacon vs medium asset
    (0.99, "low", 1, 0.0891),       # low-value noise stays tiny
])
def test_base_score_rows(conf, crit, sev, expected):
    assert base_score(conf, crit, sev) == pytest.approx(expected)


def test_base_score_rejects_bad_inputs():
    with pytest.raises(ValueError, match="confidence"):
        base_score(1.5, "critical", 3)
    with pytest.raises(ValueError, match="severity"):
        base_score(0.5, "high", 6)
    with pytest.raises(KeyError):
        base_score(0.5, "unknown_crit", 3)


def test_apply_penalties_clamps_both_ends():
    assert apply_penalties(0.95, [-0.15, -0.20]) == pytest.approx(0.60)
    assert apply_penalties(0.98, [-0.15, -0.20]) == pytest.approx(0.63)
    assert apply_penalties(0.05, [0.0]) == pytest.approx(0.05)
    assert apply_penalties(1.0, [0.5]) == 1.0          # clamp high
    assert apply_penalties(0.02, [-0.5]) == 0.0        # clamp low


# --------------------------------------------------------------------- #
# CALIBRATION TABLE (Q1 binding): canonical scenarios -> documented bands
# --------------------------------------------------------------------- #
@pytest.mark.parametrize("label,conf,crit,sev,penalties,expected_band", [
    ("tierA brute force conf>=0.93 vs critical asset reaches human band",
     0.93, "critical", 4, [], "human"),
    ("full-confidence volumetric DoS vs critical asset reaches auto band",
     1.0, "critical", 5, [], "auto"),
    ("c2 beacon vs medium asset stays below auto band",
     0.9, "medium", 4, [], "log_only"),
    ("blind-spot penalty can drop an auto-band score into human band",
     1.0, "critical", 5, [PENALTY_BLIND_SPOT_VLAN], "human"),
    ("nat fallback drops full-confidence DoS out of the auto band (pre-band)",
     1.0, "critical", 5, [PENALTY_NAT_FALLBACK], "human"),
])
def test_calibration_table(label, conf, crit, sev, penalties, expected_band):
    score = apply_penalties(base_score(conf, crit, sev), list(penalties))
    assert band(score) == expected_band, label


def test_bands_boundaries_exact():
    assert band(0.90) == "auto"
    assert band(0.899999) == "human"
    assert band(0.70) == "human"
    assert band(0.699999) == "log_only"
