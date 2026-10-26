"""Operator-maintained seasonal calendar loader (M2, D2).

seasonal_calendar.yaml is a SIBLING of config.yaml — the §8 schema stays
frozen. Validation shares the main loader's fail-closed discipline and its
EXACT error format: offending key + valid keys + "(ref §8)". We reuse
ConfigError itself so there is no second error style anywhere.

Policy (operator decision):
  * absent file  -> neutral multipliers + ONE structured warning line
                     (absence is not corrupt data; P4 degrade gracefully);
  * invalid file -> refuse boot with ConfigError;
  * overlapping overrides -> LAST entry in file order wins, plus one
    structured warning line (deterministic, never silent stacking).
"""
from __future__ import annotations

import math
from datetime import date
from pathlib import Path
from typing import Any

import yaml

from sentinel.config.loader import REF, ConfigError
from sentinel.logging_setup import get_logger

log = get_logger("sentinel.baseline.calendar")

_ENTRY_KEYS = ("end_date", "multipliers", "start_date")
_TOP_KEYS = ("overrides",)


def _iso_date(path_key: str, value: Any) -> date:
    """Strict ISO date parse; anything else refuses boot."""
    if not isinstance(value, str):
        raise ConfigError(
            f"seasonal_calendar.{path_key}: expected ISO date string "
            f"(YYYY-MM-DD), got {type(value).__name__} {value!r}; "
            f"valid keys: {', '.join(_ENTRY_KEYS)} {REF}"
        )
    try:
        return date.fromisoformat(value)
    except ValueError as exc:
        raise ConfigError(
            f"seasonal_calendar.{path_key}: invalid ISO date {value!r} "
            f"({exc}); valid keys: {', '.join(_ENTRY_KEYS)} {REF}"
        ) from exc


def _validate_entry(index: int, raw: Any) -> tuple[date, date, dict[str, float]]:
    """Validate one override entry; returns (start, end, multipliers)."""
    where = f"overrides[{index}]"
    if not isinstance(raw, dict):
        raise ConfigError(
            f"seasonal_calendar.{where}: expected a mapping, got "
            f"{type(raw).__name__}; valid keys: {', '.join(_ENTRY_KEYS)} {REF}"
        )

    unknown = sorted(set(raw) - set(_ENTRY_KEYS))
    if unknown:
        raise ConfigError(
            f"seasonal_calendar.{where}: unknown key(s) {', '.join(unknown)}; "
            f"valid keys: {', '.join(_ENTRY_KEYS)} {REF}"
        )
    missing = [k for k in _ENTRY_KEYS if k not in raw]
    if missing:
        raise ConfigError(
            f"seasonal_calendar.{where}: required key(s) missing: "
            f"{', '.join(missing)}; valid keys: {', '.join(_ENTRY_KEYS)} {REF}"
        )

    start = _iso_date(f"{where}.start_date", raw["start_date"])
    end = _iso_date(f"{where}.end_date", raw["end_date"])
    if end < start:
        raise ConfigError(
            f"seasonal_calendar.{where}: cross-field violation — "
            f"end_date={raw['end_date']!r} must be >= "
            f"start_date={raw['start_date']!r} {REF}"
        )

    mult_raw = raw["multipliers"]
    if not isinstance(mult_raw, dict):
        raise ConfigError(
            f"seasonal_calendar.{where}.multipliers: expected a mapping of "
            f"signal_family -> float, got {type(mult_raw).__name__}; "
            f"valid keys: {', '.join(_ENTRY_KEYS)} {REF}"
        )
    multipliers: dict[str, float] = {}
    for family, value in mult_raw.items():
        key = f"{where}.multipliers.{family}"
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise ConfigError(
                f"seasonal_calendar.{key}: multiplier must be a finite "
                f"float > 0, got {value!r} ({type(value).__name__}); "
                f"valid keys: {', '.join(_ENTRY_KEYS)} {REF}"
            )
        fv = float(value)
        if not math.isfinite(fv) or fv <= 0.0:
            raise ConfigError(
                f"seasonal_calendar.{key}: multiplier must be a finite "
                f"float > 0, got {fv!r}; valid keys: {', '.join(_ENTRY_KEYS)} {REF}"
            )
        multipliers[str(family)] = fv
    return start, end, multipliers


class SeasonalOverride:
    """One validated calendar window with per-family threshold multipliers."""

    __slots__ = ("start", "end", "multipliers")

    def __init__(self, start: date, end: date, multipliers: dict[str, float]) -> None:
        self.start = start
        self.end = end
        self.multipliers = dict(multipliers)

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        return (
            f"SeasonalOverride({self.start.isoformat()}..{self.end.isoformat()}, "
            f"{self.multipliers})"
        )


def load_seasonal_calendar(
    path: str | Path | None,
) -> tuple[list[SeasonalOverride], list[str]]:
    """Load + validate the seasonal calendar.

    Returns (overrides_sorted_by_start_then_file_order, warnings). Absent
    path yields ([], [warning]); invalid content raises ConfigError.
    Overlaps are allowed; LAST entry in file order wins and is warned.
    """
    if path is None:
        return [], []

    p = Path(path)
    if not p.exists():
        warning = (
            f"seasonal_calendar_absent: {p} not found — neutral multipliers "
            f"(1.0) apply for all signal families"
        )
        log.warning("seasonal_calendar_absent", path=str(p))
        return [], [warning]

    try:
        raw = yaml.safe_load(p.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise ConfigError(f"seasonal_calendar: invalid YAML syntax ({exc}) {REF}") from exc

    if raw is None:  # empty file == no overrides, same as absent
        return [], []

    if not isinstance(raw, dict):
        raise ConfigError(
            f"seasonal_calendar: expected a YAML mapping at top level, got "
            f"{type(raw).__name__}; valid keys: {', '.join(_TOP_KEYS)} {REF}"
        )

    unknown = sorted(set(raw) - set(_TOP_KEYS))
    if unknown:
        raise ConfigError(
            f"seasonal_calendar: unknown top-level key(s) {', '.join(unknown)}; "
            f"valid keys: {', '.join(_TOP_KEYS)} {REF}"
        )

    entries_raw = raw.get("overrides")
    if entries_raw is None:
        raise ConfigError(
            f"seasonal_calendar.overrides: required section missing; "
            f"valid keys: {', '.join(_TOP_KEYS)} {REF}"
        )
    if not isinstance(entries_raw, list):
        raise ConfigError(
            f"seasonal_calendar.overrides: expected a list of override "
            f"entries, got {type(entries_raw).__name__}; "
            f"valid keys: {', '.join(_TOP_KEYS)} {REF}"
        )

    overrides: list[SeasonalOverride] = []
    warnings: list[str] = []
    for i, entry in enumerate(entries_raw):
        start, end, multipliers = _validate_entry(i, entry)
        overrides.append(SeasonalOverride(start, end, multipliers))

    # Deterministic overlap resolution: LAST entry in file order wins.
    for i in range(len(overrides)):
        for j in range(i + 1, len(overrides)):
            a, b = overrides[i], overrides[j]
            if b.start <= a.end and a.start <= b.end:
                warnings.append(
                    f"seasonal_calendar_overlap: overrides[{i}] "
                    f"({a.start}..{a.end}) overlaps overrides[{j}] "
                    f"({b.start}..{b.end}); the LATER entry (index {j}) wins"
                )
                log.warning("seasonal_calendar_overlap",
                            loser_index=i, winner_index=j)

    return overrides, warnings
