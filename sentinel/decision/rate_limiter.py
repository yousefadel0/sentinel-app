"""G4 rate limiter — in-memory sliding windows on the INJECTED clock (D3).

Windows: max_blocks_per_min and max_blocks_per_hour (§8 limits). Breach is a
fact the engine consumes; persistence lands with the M6 audit store.
No wall-clock reads anywhere (clarification 2).
"""
from __future__ import annotations

from datetime import datetime, timedelta


class RateLimiter:
    """Counts block actions inside per-minute / per-hour windows."""

    def __init__(self, max_per_min: int, max_per_hour: int) -> None:
        if max_per_min < 1 or max_per_hour < 1:
            raise ValueError("limits must be >= 1")
        self._max_min = max_per_min
        self._max_hour = max_per_hour
        self._blocks: list[datetime] = []

    def _count(self, now: datetime, window: timedelta) -> int:
        """Non-destructive count inside the sliding window.

        Must NOT mutate shared state between the two window checks — a
        destructive per-minute prune would erase the hour window's history.
        """
        cutoff = now - window
        return sum(1 for ts in self._blocks if ts > cutoff)

    def prune(self, now: datetime) -> None:
        """Drop entries older than the largest window (housekeeping only)."""
        cutoff = now - timedelta(hours=1)
        self._blocks = [ts for ts in self._blocks if ts > cutoff]

    def would_breach(self, now: datetime) -> bool:
        """True iff recording one more block NOW would exceed either limit."""
        per_min = self._count(now, timedelta(minutes=1))
        per_hour = self._count(now, timedelta(hours=1))
        return per_min + 1 > self._max_min or per_hour + 1 > self._max_hour

    def record_block(self, now: datetime) -> None:
        """Record one executed/auto-approved block at time `now`."""
        self._blocks.append(now)

    def breach_reason(self, now: datetime) -> str | None:
        """Which window is full — for the internal alarm detail (G4)."""
        if self._count(now, timedelta(minutes=1)) + 1 > self._max_min:
            return "max_blocks_per_min"
        if self._count(now, timedelta(hours=1)) + 1 > self._max_hour:
            return "max_blocks_per_hour"
        return None
