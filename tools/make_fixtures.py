"""Committed replay-slice fixture builder (M6, GAP 2).

Produces a deterministic CICIDS-style DDoS slice stand-in:

    <out>/ddos.eve.jsonl   N volume_spike alert records from k spoofed
                           sources against one victim (10.0.0.4),
                           seed-controlled and byte-stable;
    <out>/manifest.json    slice identity consumed by the pilot runner's
                           replay path: {"slice_id", "source", "flows"}
                           with per-flow {flow_id, family, dst_ip,
                           first_attack_ts}.

CLI: python -m tools.make_fixtures --out DIR [--seed 42] [--attack-events 40]

Determinism contract: same --seed + --attack-events => byte-identical
files forever (rng_for() from tools.attackers.common).
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from tools.attackers.common import make_eve_record, rng_for, write_events

VICTIM_IP = "10.0.0.4"
SLICE_ID = "cicids2017-friday-ddos-slice"
SOURCE_NOTE = "CICIDS2017-replay (synthetic stand-in, committed)"


def build_slice(*, seed: int = 42, attack_events: int = 40,
                spoofed_sources: int = 8):
    """Return (events, manifest) for the ddos slice — pure, no I/O."""
    rng = rng_for(seed, "ddos-slice")
    events = []
    first_attack_ts = None
    for i in range(attack_events):
        src = f"198.18.{i % spoofed_sources}.{(i // spoofed_sources) % 254 + 1}"
        offset = float(i * 2)          # 2 s apart, strictly increasing
        rec = make_eve_record(
            ts_offset=offset,
            src_ip=src,
            dst_ip=VICTIM_IP,
            src_port=rng.randint(40000, 60000),
            dst_port=443,
            proto="tcp",
            signal="volume_spike",
            family="ddos_volumetric",
            confidence=0.9,
            severity=5,
            signature_id=2200001 + (i % 4),
        )
        if first_attack_ts is None:
            first_attack_ts = rec["timestamp"]
        events.append(rec)
    manifest = {
        "slice_id": SLICE_ID,
        "source": SOURCE_NOTE,
        "flows": [{
            "flow_id": f"{SLICE_ID}#ddos-volumetric",
            "family": "ddos_volumetric",
            "dst_ip": VICTIM_IP,
            "first_attack_ts": first_attack_ts,
        }],
    }
    return events, manifest


def main(argv=None):
    ap = argparse.ArgumentParser(prog="make_fixtures")
    ap.add_argument("--out", required=True, type=Path,
                    help="output directory (created if missing)")
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--attack-events", type=int, default=40)
    args = ap.parse_args(argv)

    events, manifest = build_slice(
        seed=args.seed, attack_events=args.attack_events)
    out = args.out
    n_bytes = write_events(out / "ddos.eve.jsonl", events)
    blob = json.dumps(manifest, indent=2, sort_keys=True) + "\n"
    (out / "manifest.json").write_text(blob, encoding="utf-8")
    print(f"wrote {len(events)} events ({n_bytes} bytes) "
          f"+ manifest to {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
