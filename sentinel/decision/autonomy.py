"""Autonomy ladder L0–L3 (§6) with MANUAL upgrades and KPI-driven downgrades.

D4: downgrade KPIs are EXPLICIT function inputs — this module never computes
FP rates itself; the measurement pipeline is M6's concern.
Upgrades are ALWAYS manual operator actions gated on KPI evidence (never
automatic). SOC alerts in M3 are structured JSON log lines (Q6).
"""
from __future__ import annotations

from sentinel.logging_setup import get_logger

log = get_logger("sentinel.decision.autonomy")

LEVELS = ("L0", "L1", "L2", "L3")
FP_DOWNGRADE_THRESHOLD = 5.0     # FP% > 5   -> level - 1
FP_SEVERE_THRESHOLD = 8.0        # FP% > 8   -> level - 2 + immediate SOC alert
CIRCUIT_BREAKER_ROLLBACKS = 3    # consecutive rollbacks -> level - 1


class AutonomyController:
    """Holds the per-deployment autonomy level (default L0, §8 config)."""

    def __init__(self, level: int = 0) -> None:
        if not 0 <= level <= 3:
            raise ValueError(f"autonomy_level must be 0..3, got {level}")
        self._level = level

    @property
    def level(self) -> int:
        return self._level

    def upgrade_manual(self, target: int, kpi_evidence: str) -> None:
        """MANUAL operator upgrade; gated on stated KPI evidence (§11).

        Refuses non-adjacent jumps and any automatic invocation path.
        """
        if target != self._level + 1 or target > 3:
            raise ValueError(
                f"manual upgrades are one step at a time "
                f"(current L{self._level}, requested L{target})"
            )
        if not kpi_evidence:
            raise ValueError("upgrade requires KPI evidence citation")
        self._level = target
        log.info("autonomy_upgraded", new_level=f"L{target}",
             evidence=kpi_evidence)

    def _downgrade(self, steps: int, reason: str, detail: dict) -> None:
        new_level = max(0, self._level - steps)
        changed = new_level != self._level
        self._level = new_level
        # immediate SOC alert as structured JSON line (Q6 — M3 scope)
        log.error("soc_alert", reason=reason,
                  level_now=f"L{new_level}", level_changed=changed, **detail)

    def apply_kpi_signal(
        self,
        fp_rate_14d: float | None = None,
        consecutive_rollbacks: int | None = None,
    ) -> None:
        """Apply operator-supplied rolling-14-day KPIs (D4).

        FP% >5% → −1 · FP% >8% → −2 (floor L0) + SOC alert.
        3 consecutive rolled-back actions → −1 (circuit breaker, G5).
        """
        if fp_rate_14d is not None:
            if fp_rate_14d > FP_SEVERE_THRESHOLD:
                self._downgrade(2, "fp_rate_breach",
                                {"fp_rate_14d": fp_rate_14d})
            elif fp_rate_14d > FP_DOWNGRADE_THRESHOLD:
                self._downgrade(1, "fp_rate_breach",
                                {"fp_rate_14d": fp_rate_14d})
        if consecutive_rollbacks is not None and \
                consecutive_rollbacks >= CIRCUIT_BREAKER_ROLLBACKS:
            self._downgrade(1, "circuit_breaker",
                            {"consecutive_rollbacks": consecutive_rollbacks})
