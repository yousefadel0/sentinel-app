"""Baseline engine (M2): observed rates over a rolling window + seasonal
thresholds.

Pure math, zero decision-engine leakage (Rule 4): outputs are raw
components — mean_rate, sigma, threshold, seasonal_multiplier. No scores,
no actions, no playbooks.

Clock discipline (D1): "now" is ALWAYS an injected callable returning an
aware datetime; tests simulate any 14-day window instantly, including
crossing override dates and ramp boundaries.

Threshold shape (operator-accepted):
    threshold(family, t) = (mean_rate + K_SIGMA * sigma) * multiplier(t)
where mean/sigma come from per-DAY counts inside the trailing WINDOW_DAYS
window ending at t (inclusive), and multiplier(t) applies the operator
calendar with a linear adoption ramp:
    day 0 of an override -> 1.0 (neutral)
    day RAMP_DAYS        -> full target value
    holds until end_date, then back to neutral.
"""
from __future__ import annotations

import math
import statistics
from collections import defaultdict
from dataclasses import dataclass
from datetime import date, datetime, timedelta, timezone
from typing import Callable, Iterable

from sentinel.baseline.calendar import SeasonalOverride, load_seasonal_calendar

K_SIGMA = 3          # fixed k (operator-accepted); documented module constant
WINDOW_DAYS = 14     # rolling observation window (§10-M2 / §6 L0 evidence)
RAMP_DAYS = 14       # phased adoption ramp length for seasonal multipliers


@dataclass(frozen=True)
class Threshold:
    """Raw baseline components for one signal family — nothing more."""

    signal_family: str
    mean_rate: float            # mean daily count over the window
    sigma: float                # population std-dev of daily counts
    threshold: float            # (mean + K_SIGMA*sigma) * seasonal_multiplier
    seasonal_multiplier: float  # 1.0 when neutral / no override applies
    window_days_observed: int   # days with at least one observation record


class BaselineEngine:
    """Rolling 14-day per-family rate baseline with seasonal thresholds."""

    def __init__(
        self,
        clock: Callable[[], datetime],
        calendar_path: str | None = None,
    ) -> None:
        if not callable(clock):
            raise TypeError("clock must be a callable returning datetime")
        self._clock = clock
        self._overrides, boot_warnings = load_seasonal_calendar(calendar_path)
        self.boot_warnings: list[str] = list(boot_warnings)
        # observations[family][date] -> total count that day
        self._observations: dict[str, dict[date, float]] = defaultdict(dict)

    # ------------------------------------------------------------------ feed

    def record_observation(self, ts: datetime, signal_family: str, count: int) -> None:
        """Record one observed count for a family at time ts.

        Same-day records accumulate; out-of-order feeds are fine because the
        window is computed from dates, never from insertion order.
        """
        if isinstance(ts, datetime) and ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        if count < 0:
            raise ValueError(f"count must be >= 0, got {count}")
        if not signal_family:
            raise ValueError("signal_family must be non-empty")
        day = ts.date() if isinstance(ts, datetime) else ts
        self._observations[signal_family][day] = (
            self._observations[signal_family].get(day, 0.0) + count
        )

    # ------------------------------------------------------------ thresholds

    def _multiplier_for(self, family: str, today: date) -> tuple[float, SeasonalOverride | None]:
        """Seasonal multiplier for family on `today`.

        Linear ramp: neutral 1.0 at override start (day 0), full target at
        day RAMP_DAYS, held until end_date, neutral outside every override.
        Overlapping overrides: LAST in file order wins (calendar loader
        already warned); earlier overlapping entries never partially apply.
        """
        winner: SeasonalOverride | None = None
        for ov in self._overrides:  # file order; later entries overwrite
            if ov.start <= today <= ov.end and family in ov.multipliers:
                winner = ov
        if winner is None or family not in winner.multipliers:
            return 1.0, None

        target = winner.multipliers[family]
        elapsed = (today - winner.start).days
        fraction = min(1.0, elapsed / RAMP_DAYS)
        return 1.0 + (target - 1.0) * fraction, winner

    def threshold(self, signal_family: str) -> Threshold:
        """Compute current baseline components for one family."""
        now = self._clock()
        if now.tzinfo is None:
            now = now.replace(tzinfo=timezone.utc)
        today = now.date()

        days = self._observations.get(signal_family, {})
        window_start = today - timedelta(days=WINDOW_DAYS - 1)
        counts = [
            days[d]
            for d in sorted(days)
            if window_start <= d <= today
        ]

        if counts:
            mean_rate = statistics.fmean(counts)
            sigma = statistics.pstdev(counts) if len(counts) > 1 else 0.0
        else:
            mean_rate = 0.0
            sigma = 0.0

        multiplier, _winner = self._multiplier_for(signal_family, today)
        base = mean_rate + K_SIGMA * sigma
        return Threshold(
            signal_family=signal_family,
            mean_rate=mean_rate,
            sigma=sigma,
            threshold=base * multiplier,
            seasonal_multiplier=multiplier,
            window_days_observed=len(counts),
        )

    def thresholds(self, families: Iterable[str]) -> dict[str, Threshold]:
        """Convenience bulk form of threshold()."""
        return {f: self.threshold(f) for f in families}
