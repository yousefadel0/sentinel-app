"""Shared builders for decision tests (no YAML — ConfigView is built literally)."""
from __future__ import annotations

import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from sentinel.decision import (  # noqa: E402
    AutonomyController,
    ConfigView,
    DecisionEngine,
    RateLimiter,
)
from sentinel.models import Alert, AlertMeta, AssetHint, ConfidenceTier, SourceRef


class FakeClock:
    """Injected clock (D3) — tests move it anywhere, instantly."""

    def __init__(self, start: datetime | None = None) -> None:
        self._now = start or datetime(2026, 4, 1, 12, 0, tzinfo=timezone.utc)

    def advance(self, seconds: float = 0.0, minutes: float = 0.0) -> None:
        self._now += timedelta(seconds=seconds, minutes=minutes)

    def __call__(self) -> datetime:
        return self._now


def config_view(**overrides) -> ConfigView:
    """customer-A §8 values; overrides for targeted scenarios."""
    base = dict(
        critical_assets=frozenset({"10.0.0.4", "10.0.0.5"}),
        monitored_vlans=frozenset({"prod", "mgmt"}),
        asymmetric_risk="medium",
        max_blocks_per_min=5,
        max_blocks_per_hour=20,
        autonomy_level=0,
        auto_threshold=0.95,
        human_threshold=0.70,
        report_threshold=0.0,
    )
    base.update(overrides)
    return ConfigView(**base)


_SEQ = iter(range(1, 100000))


def alert(
    signal: str,
    conf: float,
    tier: ConfidenceTier = ConfidenceTier.A,
    crit: str | None = "high",
    dst: str = "10.0.0.99",
    vlan: str | None = "prod",
) -> Alert:
    n = next(_SEQ)
    return Alert(
        alert_id=f"a-{n}",
        ts="2026-04-01T12:00:00+00:00",
        source=SourceRef(adapter="eve_json", ref=f"eve.json:{n}"),
        src_ip="203.0.113.7",
        dst_ip=dst,
        src_port=44444,
        dst_port=22,
        protocol="tcp",
        vlan=vlan,
        asset_hint=AssetHint(resolved_hostname=None, asset_id=None,
                             criticality=crit),
        signals=(signal,),
        confidence_raw=conf,
        confidence_tier=tier,
        meta=AlertMeta(packet_count=n),
    )


class IncidentStub:
    """Minimal _IncidentLike — correlator.Incident satisfies this too."""

    def __init__(self, alerts, dst_ip: str = "10.0.0.99") -> None:
        self.incident_id = f"inc-{next(_SEQ)}"
        self.alerts = tuple(alerts)
        self.dst_ip = dst_ip


def engine(cfg: ConfigView | None = None, clock: FakeClock | None = None,
           limiter: RateLimiter | None = None) -> tuple[DecisionEngine, FakeClock]:
    clk = clock or FakeClock()
    eng = DecisionEngine(
        config_view=cfg or config_view(),
        clock=clk,
        rate_limiter=limiter or RateLimiter(5, 20),
        controller=AutonomyController(level=0),
    )
    return eng, clk
