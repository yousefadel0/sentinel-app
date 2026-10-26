"""Baseline package (M2): rolling-window rates + seasonal thresholds.

Public surface:
    BaselineEngine, Threshold, K_SIGMA, WINDOW_DAYS,
    load_seasonal_calendar, SeasonalOverride
"""
from sentinel.baseline.calendar import (
    SeasonalOverride,
    load_seasonal_calendar,
)
from sentinel.baseline.engine import (
    K_SIGMA,
    WINDOW_DAYS,
    BaselineEngine,
    Threshold,
)

__all__ = [
    "K_SIGMA",
    "WINDOW_DAYS",
    "BaselineEngine",
    "SeasonalOverride",
    "Threshold",
    "load_seasonal_calendar",
]
