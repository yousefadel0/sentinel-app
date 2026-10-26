"""Detector evaluation harness — labeled synthetic scenarios -> metrics.

Generates deterministic (seeded) attack and benign flow streams at the
normalized-Alert level, runs them through a fresh ``DetectorSuite`` in
5-second event-time batches (exactly how the daemon feeds it), and scores:

* recall / detection delay (MTTD, event-time seconds) per attack family;
* precision per family and the false-positive count on benign-only traffic.

HONEST SCOPE: these are synthetic scenarios authored alongside the
detectors. They guard against regressions and expose threshold trade-offs;
they are NOT a substitute for evaluation on real captures (CICIDS/PCAPs),
which the same ``Scenario`` interface can host later.
"""
from __future__ import annotations

import random
import statistics
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone

from sentinel.detectors import DetectorConfig, DetectorSuite
from sentinel.detectors.dns import dns_signals
from sentinel.models import (Alert, AlertMeta, AssetHint, ConfidenceTier,
                             SourceRef)

T0 = datetime(2026, 1, 15, 9, 0, 0, tzinfo=timezone.utc)
FAMILIES = ("scan", "auth_fail_burst", "volume_spike", "beacon_periodic",
            "dns_tunneling")


def _alert(t: float, src: str, dst: str, dport: int, *, proto="tcp",
           signals=("zeek_conn",), rng: random.Random) -> Alert:
    return Alert(
        alert_id=str(uuid.UUID(int=rng.getrandbits(128), version=4)),
        ts=(T0 + timedelta(seconds=t)).isoformat(),
        source=SourceRef(adapter="zeek_conn", ref="eval"),
        src_ip=src, dst_ip=dst, src_port=rng.randint(32768, 60999),
        dst_port=dport, protocol=proto, vlan=None, asset_hint=AssetHint(),
        signals=tuple(signals), confidence_raw=0.5,
        confidence_tier=ConfidenceTier.A,
        meta=AlertMeta(None, None, None, None))


@dataclass
class Scenario:
    name: str
    family: str | None                # None => benign
    events: list[Alert]
    attacker: str = ""                # expected src (dst for volume_spike)
    victim: str = ""
    start: float = 0.0                # event-time of first attack event


# -- attack generators -------------------------------------------------------

def scan(rng, base=100.0) -> Scenario:
    src = f"203.0.113.{rng.randint(2, 250)}"
    ev = [_alert(base + i * 0.2, src, f"10.0.{rng.randint(1, 3)}.{10 + i % 60}",
                 rng.choice((22, 80, 443, 445, 3389, 8080)), rng=rng)
          for i in range(80)]
    return Scenario("scan", "scan", ev, src, "", base)


def brute(rng, base=100.0) -> Scenario:
    src, dst = f"198.51.100.{rng.randint(2, 250)}", "10.0.0.4"
    ev = [_alert(base + i * rng.uniform(1.5, 3.0), src, dst, 22, rng=rng)
          for i in range(40)]
    return Scenario("brute_force", "auth_fail_burst", ev, src, dst, base)


def ddos(rng, base=100.0) -> Scenario:
    dst = "10.0.0.20"
    srcs = [f"192.0.2.{i}" for i in range(1, 201)] + \
           [f"198.18.{i // 250}.{i % 250 + 1}" for i in range(200)]
    ev = [_alert(base + rng.uniform(0, 40), rng.choice(srcs), dst, 443, rng=rng)
          for _ in range(1500)]
    return Scenario("ddos", "volume_spike", ev, "", dst, base)


def beacon(rng, base=60.0) -> Scenario:
    src, dst = "10.0.2.31", f"185.220.101.{rng.randint(2, 250)}"
    period = rng.choice((30.0, 60.0, 120.0))
    ev, t = [], base
    for _ in range(24):
        ev.append(_alert(t, src, dst, 443, rng=rng))
        t += period * (1 + rng.uniform(-0.03, 0.03))
    return Scenario("c2_beacon", "beacon_periodic", ev, src, dst, base)


def _tunnel_name(rng) -> str:
    alphabet = "abcdefghijklmnopqrstuvwxyz234567"
    return "".join(rng.choice(alphabet) for _ in range(44)) + ".t.example.net"


def dns_tunnel(rng, base=100.0) -> Scenario:
    src, resolver = "10.0.2.77", "10.0.0.5"
    ev = []
    for i in range(60):
        sig = ("zeek_dns", *dns_signals(_tunnel_name(rng)))
        ev.append(_alert(base + i * 1.5, src, resolver, 53, proto="udp",
                         signals=sig, rng=rng))
    return Scenario("dns_tunneling", "dns_tunneling", ev, src, resolver, base)


# -- benign background -------------------------------------------------------

_BENIGN_NAMES = (
    "www.example.com", "mail.google.com", "d1a2b3c4e5f6.cloudfront.net",
    "e2e-prod-eu-west-1-api-gateway-service.internal.example.com",
    "update.microsoft.com", "login.live.com", "a1b2c3d4.akamaiedge.net",
    "clients4.google.com", "teams.events.data.microsoft.com",
)


def benign(rng, duration=1500.0) -> Scenario:
    ev: list[Alert] = []
    servers = [f"172.16.0.{i}" for i in range(10, 30)]
    for c in range(60):                              # ordinary browsing
        src = f"10.0.1.{10 + c}"
        t = rng.uniform(0, 60)
        while t < duration:
            ev.append(_alert(t, src, rng.choice(servers),
                             rng.choice((80, 443)), rng=rng))
            t += rng.expovariate(1 / 25.0)
    t = 0.0                                          # NTP, strictly periodic
    while t < duration:
        ev.append(_alert(t, "10.0.1.200", "162.159.200.1", 123,
                         proto="udp", rng=rng))
        t += 64.0
    t = 5.0                                          # jittery updater poll
    while t < duration:
        ev.append(_alert(t, "10.0.1.201", "13.107.4.50", 443, rng=rng))
        t += rng.uniform(36.0, 84.0)
    for c in range(30):                              # popular internal site
        for k in range(10):
            ev.append(_alert(200 + rng.uniform(0, 120), f"10.0.1.{100 + c}",
                             "10.0.0.30", 443, rng=rng))
    for k in range(6):                               # admin SSH hops
        ev.append(_alert(300 + k * 20, "10.0.1.250", "10.0.0.4", 22, rng=rng))
    for t in range(0, int(duration), 3):             # normal DNS
        ev.append(_alert(float(t), f"10.0.1.{10 + t % 60}", "10.0.0.5", 53,
                         proto="udp",
                         signals=("zeek_dns",
                                  *dns_signals(rng.choice(_BENIGN_NAMES))),
                         rng=rng))
    return Scenario("benign", None, ev)


# -- scoring -----------------------------------------------------------------

@dataclass
class Report:
    per_family: dict[str, dict] = field(default_factory=dict)
    benign_false_positives: int = 0
    benign_runs: int = 0

    def to_dict(self) -> dict:
        return {"per_family": self.per_family,
                "benign_false_positives": self.benign_false_positives,
                "benign_runs": self.benign_runs}


def run_scenario(sc: Scenario, cfg: DetectorConfig | None = None,
                 batch_s: int = 5) -> list[Alert]:
    """Feed events in ``batch_s`` event-time batches; return emitted alerts."""
    suite = DetectorSuite(cfg or DetectorConfig())
    ordered = sorted(sc.events, key=lambda a: a.ts)
    out: list[Alert] = []
    batch: list[Alert] = []
    cur = None
    for a in ordered:
        sec = (_dt(a.ts).timestamp() // batch_s)
        if cur is not None and sec != cur:
            suite.ingest(batch)
            out.extend(suite.detect())
            batch = []
        cur = sec
        batch.append(a)
    suite.ingest(batch)
    out.extend(suite.detect())
    return out


def _dt(ts: str) -> datetime:
    return datetime.fromisoformat(ts)


def _matches(sc: Scenario, alert: Alert) -> bool:
    if alert.signals[0] != sc.family:
        return False
    if sc.family == "volume_spike":
        return alert.dst_ip == sc.victim
    return alert.src_ip == sc.attacker


def evaluate(seeds=range(10), cfg: DetectorConfig | None = None) -> Report:
    rep = Report()
    gens = {"scan": scan, "auth_fail_burst": brute, "volume_spike": ddos,
            "beacon_periodic": beacon, "dns_tunneling": dns_tunnel}
    stats = {f: {"tp": 0, "fn": 0, "fp": 0, "delays": []} for f in FAMILIES}
    for seed in seeds:
        rng = random.Random(f"eval:{seed}")
        bg = benign(rng)
        for fam, gen in gens.items():
            sc = gen(rng)
            mixed = Scenario(sc.name, sc.family, bg.events + sc.events,
                             sc.attacker, sc.victim, sc.start)
            emitted = run_scenario(mixed, cfg)
            hits = [a for a in emitted if _matches(sc, a)]
            if hits:
                first = min(hits, key=lambda a: a.ts)
                delay = (datetime.fromisoformat(first.ts) - T0).total_seconds() - sc.start
                stats[fam]["tp"] += 1
                stats[fam]["delays"].append(max(delay, 0.0))
            else:
                stats[fam]["fn"] += 1
            for a in emitted:
                if not _matches(sc, a):
                    stats[a.signals[0]]["fp"] += 1
        rep.benign_runs += 1
        rep.benign_false_positives += len(run_scenario(bg, cfg))
    for fam, st in stats.items():
        tp, fn, fp = st["tp"], st["fn"], st["fp"]
        rep.per_family[fam] = {
            "recall": round(tp / (tp + fn), 3) if tp + fn else None,
            "precision": round(tp / (tp + fp), 3) if tp + fp else None,
            "false_positives": fp,
            "mttd_median_s": (round(statistics.median(st["delays"]), 1)
                              if st["delays"] else None),
            "runs": tp + fn,
        }
    return rep


def main() -> int:  # pragma: no cover - CLI convenience
    import json
    print(json.dumps(evaluate().to_dict(), indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
