"""Detector pipeline throughput benchmark.

    python -m sentinel.evaluation.perf [events_per_s] [seconds]

Feeds ordinary flow records (no attack) at a fixed event-time rate in
1-second batches — the daemon's cadence — and reports how long each
``ingest + detect`` cycle takes. The daemon stays real-time while the cycle
time is below its poll interval (1 s).
"""
from __future__ import annotations

import random
import statistics
import sys
import time

from sentinel.detectors import DetectorSuite
from sentinel.evaluation.harness import _alert


def run(rate: int = 2000, seconds: int = 120) -> dict:
    rng = random.Random(7)
    suite = DetectorSuite()
    cycle_ms: list[float] = []
    total = 0
    for sec in range(seconds):
        batch = [_alert(sec + i / rate, f"10.0.{rng.randint(0, 3)}.{rng.randint(1, 250)}",
                        f"172.16.{rng.randint(0, 3)}.{rng.randint(1, 250)}",
                        rng.choice((80, 443, 53, 8080)), rng=rng)
                 for i in range(rate)]
        t0 = time.perf_counter()
        suite.ingest(batch)
        suite.detect()
        cycle_ms.append((time.perf_counter() - t0) * 1000)
        total += len(batch)
    tail = cycle_ms[-20:]
    return {"events_per_s": rate, "seconds": seconds, "events": total,
            "tracked_events": suite.tracked_events,
            "cycle_ms_median": round(statistics.median(cycle_ms), 1),
            "cycle_ms_last20_mean": round(statistics.fmean(tail), 1),
            "cycle_ms_max": round(max(cycle_ms), 1),
            "realtime": statistics.fmean(tail) < 1000}


def main(argv: list[str]) -> int:  # pragma: no cover - CLI convenience
    import json
    rate = int(argv[0]) if argv else 2000
    secs = int(argv[1]) if len(argv) > 1 else 120
    print(json.dumps(run(rate, secs), indent=2))
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main(sys.argv[1:]))
