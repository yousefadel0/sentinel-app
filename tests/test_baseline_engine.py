"""Gate B (§10-M2): baseline thresholds shift correctly on seasonal
override dates, with the phased 14-day adoption ramp.

D1: clock is injected — any 14-day window is simulated instantly.
"""
from __future__ import annotations

import math
from datetime import date, datetime, timedelta, timezone

import pytest

from sentinel.baseline import (
    K_SIGMA,
    WINDOW_DAYS,
    BaselineEngine,
    Threshold,
)


class FakeClock:
    """Injected clock (D1) — tests move it anywhere, instantly."""

    def __init__(self, start: datetime) -> None:
        self._now = start

    def advance(self, **kwargs: timedelta | int | float) -> None:
        delta = kwargs.get("delta")
        if isinstance(delta, timedelta):
            self._now += delta
        else:
            days = kwargs.get("days", 0)
            self._now += timedelta(days=days)

    def set_date(self, d: date) -> None:
        self._now = datetime(d.year, d.month, d.day, 12, 0, tzinfo=timezone.utc)

    def __call__(self) -> datetime:
        return self._now


def feed_constant(engine: BaselineEngine, family: str, days: int, per_day: int,
                  end: datetime) -> None:
    """Feed `per_day` counts daily for the last `days` days ending at `end`."""
    # feed the LAST `days` days INCLUDING the end day itself so that a
    # clock at `end` sees exactly `days` observed days in-window
    for i in range(days):
        day = (end - timedelta(days=i)).replace(hour=3, minute=0)
        engine.record_observation(day, family, per_day)


NEUTRAL_CAL = "tests/fixtures/calendar/empty.yaml"
SCAN_CAL = "tests/fixtures/calendar/scan_x2.yaml"


# ------------------------------------------------------- core window math


def test_mean_sigma_threshold_exact_values():
    clock = FakeClock(datetime(2026, 6, 15, 12, 0, tzinfo=timezone.utc))
    eng = BaselineEngine(clock, NEUTRAL_CAL)
    # 14 days of exactly 10/day -> mean 10.0, sigma 0.0
    feed_constant(eng, "auth_fail_burst", WINDOW_DAYS, 10, clock())
    t = eng.threshold("auth_fail_burst")
    assert isinstance(t, Threshold)
    assert t.mean_rate == pytest.approx(10.0)
    assert t.sigma == pytest.approx(0.0)
    assert t.threshold == pytest.approx((10.0 + K_SIGMA * 0.0) * 1.0)
    assert t.seasonal_multiplier == 1.0
    assert t.window_days_observed == WINDOW_DAYS


def test_sigma_nonzero_and_k_factor_in_threshold():
    clock = FakeClock(datetime(2026, 6, 15, 12, 0, tzinfo=timezone.utc))
    eng = BaselineEngine(clock, NEUTRAL_CAL)
    counts = [4, 4, 4, 4, 4, 4, 4, 16, 16, 16, 16, 16, 16, 16]  # bimodal
    for i, c in enumerate(counts):
        day = datetime(2026, 6, 15, 3, 0, tzinfo=timezone.utc) - timedelta(days=13 - i)
        eng.record_observation(day, "scan", c)
    t = eng.threshold("scan")
    mean = sum(counts) / len(counts)
    sigma = math.sqrt(sum((c - mean) ** 2 for c in counts) / len(counts))
    assert t.mean_rate == pytest.approx(mean)
    assert t.sigma == pytest.approx(sigma)
    assert t.threshold == pytest.approx(mean + K_SIGMA * sigma)


def test_window_is_rolling_oldest_day_drops_out():
    clock = FakeClock(datetime(2026, 6, 15, 12, 0, tzinfo=timezone.utc))
    eng = BaselineEngine(clock, NEUTRAL_CAL)
    feed_constant(eng, "dns_tunneling", WINDOW_DAYS, 10, clock())
    before = eng.threshold("dns_tunneling").mean_rate
    clock.advance(days=1)
    eng.record_observation(
        datetime(2026, 6, 16, 3, 0, tzinfo=timezone.utc), "dns_tunneling", 30
    )
    after = eng.threshold("dns_tunneling")
    # day of 10 dropped out; day of 30 entered -> mean rises
    assert after.mean_rate > before
    assert after.window_days_observed == WINDOW_DAYS


def test_zero_history_family_documented_no_crash():
    eng = BaselineEngine(FakeClock(datetime(2026, 6, 15, tzinfo=timezone.utc)),
                         NEUTRAL_CAL)
    t = eng.threshold("never_seen_family")
    assert t.mean_rate == 0.0 and t.sigma == 0.0
    assert t.seasonal_multiplier == 1.0
    assert t.threshold == 0.0
    assert t.window_days_observed == 0


# ------------------------------------------------------- seasonal shifting


def test_threshold_doubles_under_x2_override_after_ramp():
    """Full ramp elapsed: threshold shifts by exactly the multiplier."""
    clock = FakeClock(datetime(2026, 7, 20, 12, 0, tzinfo=timezone.utc))
    eng = BaselineEngine(clock, SCAN_CAL)   # scan x2 from 2026-07-01..31
    feed_constant(eng, "scan", WINDOW_DAYS, 10, clock())
    neutral = (10.0 + K_SIGMA * 0.0) * 1.0
    t = eng.threshold("scan")
    assert t.seasonal_multiplier == pytest.approx(2.0)
    assert t.threshold == pytest.approx(neutral * 2.0)


def test_other_families_inherit_neutral_1_0():
    clock = FakeClock(datetime(2026, 7, 20, 12, 0, tzinfo=timezone.utc))
    eng = BaselineEngine(clock, SCAN_CAL)
    feed_constant(eng, "auth_fail_burst", WINDOW_DAYS, 8, clock())
    t = eng.threshold("auth_fail_burst")     # not in override map
    assert t.seasonal_multiplier == 1.0


# ------------------------------------------------------------------- ramp


def test_ramp_day0_neutral_day14_full_target():
    """Phased adoption: day 0 = 1.0 -> day 14 = full target (linear)."""
    start = date(2026, 7, 1)
    for offset, expected_mult in ((0, 1.0), (7, 1.5), (14, 2.0)):
        clock = FakeClock(datetime(start.year, start.month,
                                   start.day + offset, 12, 0,
                                   tzinfo=timezone.utc))
        eng = BaselineEngine(clock, SCAN_CAL)
        feed_constant(eng, "scan", WINDOW_DAYS, 10, clock())
        t = eng.threshold("scan")
        assert t.seasonal_multiplier == pytest.approx(expected_mult), (
            f"day {offset}: multiplier must be {expected_mult}"
        )
        assert t.threshold == pytest.approx((10.0) * expected_mult)


def test_ramp_holds_until_end_date_then_back_to_neutral():
    """After day-14 plateau the value holds; expiry returns to neutral."""
    # 2026-07-01..31 override; check plateau on 07-20 and expiry on 08-05
    for day, expected in ((date(2026, 7, 25), 2.0),
                          (date(2026, 8, 5), 1.0)):
        clock = FakeClock(datetime(day.year, day.month, day.day, 12, 0,
                                   tzinfo=timezone.utc))
        eng = BaselineEngine(clock, SCAN_CAL)
        feed_constant(eng, "scan", WINDOW_DAYS, 10, clock())
        assert eng.threshold("scan").seasonal_multiplier == pytest.approx(expected)


def test_before_start_date_pure_neutral_regardless_of_history():
    clock = FakeClock(datetime(2026, 6, 15, 12, 0, tzinfo=timezone.utc))
    eng = BaselineEngine(clock, SCAN_CAL)   # override starts 2026-07-01
    feed_constant(eng, "scan", WINDOW_DAYS, 10, clock())
    assert eng.threshold("scan").seasonal_multiplier == 1.0


# --------------------------------------------------------------- overlaps


def test_overlapping_overrides_last_in_file_wins_no_partial_apply(tmp_path):
    """Reminder #2: loser's multiplier must NOT partially apply."""
    cal = tmp_path / "overlap.yaml"
    cal.write_text(
        "overrides:\n"
        "  - start_date: '2026-09-05'\n"   # loser: first in file order
        "    end_date: '2026-09-30'\n"
        "    multipliers: {scan: 3.0}\n"
        "  - start_date: '2026-09-10'\n"   # winner: LAST in file order
        "    end_date: '2026-09-30'\n"
        "    multipliers: {scan: 1.5}\n",
        encoding="utf-8",
    )
    # 09-25: inside both windows AND past the winner's 14-day ramp end
    clock = FakeClock(datetime(2026, 9, 25, 12, 0, tzinfo=timezone.utc))
    eng = BaselineEngine(clock, str(cal))
    feed_constant(eng, "scan", WINDOW_DAYS, 10, clock())
    t = eng.threshold("scan")
    assert t.seasonal_multiplier == pytest.approx(1.5)   # LAST entry wins
    assert len(eng.boot_warnings) == 1                   # one warning line
    assert "seasonal_calendar_overlap" in eng.boot_warnings[0]


def test_boot_warning_for_absent_calendar_file():
    eng = BaselineEngine(FakeClock(datetime(2026, 6, 15, tzinfo=timezone.utc)),
                         "/nonexistent/seasonal_calendar.yaml")
    assert eng._overrides == []
    assert len(eng.boot_warnings) == 1
    assert "neutral" in eng.boot_warnings[0]


# ------------------------------------------------------------- shape guard


def test_threshold_shape_has_no_decision_engine_fields():
    """Rule 4 guard: raw components only — no scores/actions/playbooks."""
    eng = BaselineEngine(FakeClock(datetime(2026, 6, 15, tzinfo=timezone.utc)),
                         NEUTRAL_CAL)
    t = eng.threshold("scan")
    fields = set(t.__dataclass_fields__)
    assert fields == {
        "signal_family", "mean_rate", "sigma",
        "threshold", "seasonal_multiplier", "window_days_observed",
    }
    assert not any(f.startswith(("score", "action", "playbook"))
                   for f in fields)


def test_record_observation_validation_and_accumulation():
    eng = BaselineEngine(FakeClock(datetime(2026, 6, 15, tzinfo=timezone.utc)),
                         NEUTRAL_CAL)
    day = datetime(2026, 6, 14, 3, 0, tzinfo=timezone.utc)
    eng.record_observation(day, "scan", 5)
    eng.record_observation(day, "scan", 7)      # same-day accumulates
    assert eng.threshold("scan").mean_rate == pytest.approx(12.0)
    with pytest.raises(ValueError):
        eng.record_observation(day, "scan", -1)
    with pytest.raises(ValueError):
        eng.record_observation(day, "", 1)
