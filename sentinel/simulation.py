"""Append synthetic Zeek connection events for safe UI demonstrations."""
from __future__ import annotations

import argparse
import ipaddress
import json
import time
from datetime import datetime, timezone
from pathlib import Path


def simulate(kind: str, capture_dir: Path) -> int:
    health = capture_dir / "live-health.json"
    try:
        state = json.loads(health.read_text(encoding="utf-8"))
        fresh = time.time() - health.stat().st_mtime < 30
    except (OSError, ValueError) as exc:
        raise RuntimeError("Sentinel health is unavailable; start the dry-run daemon first") from exc
    if not fresh or state.get("enforcement", {}).get("dry_run") is not True:
        raise RuntimeError("simulation requires a fresh dry-run daemon")
    if kind not in ("scan", "brute", "ddos", "anomaly"):
        raise ValueError("attack type must be scan, brute, ddos or anomaly")
    log = capture_dir / "conn.log"
    stamp = datetime.now(timezone.utc).timestamp() - 3
    def row(index: int, src: str, dst: str, port: int) -> str:
        ipaddress.IPv4Address(src)
        ipaddress.IPv4Address(dst)
        return f"{stamp + index * .001:.6f}\t{src}\t40000\t{dst}\t{port}\ttcp\n"
    if kind == "scan":
        lines = [row(i, "203.0.113.50", f"10.2.{i // 250}.{i % 250 + 1}", 445)
                 for i in range(80)]
    elif kind == "brute":
        lines = [row(i, "198.51.100.77", "10.0.0.4", 22) for i in range(40)]
    elif kind == "ddos":
        lines = [row(i, f"192.0.2.{i % 80 + 1}", "10.0.0.20", 443)
                 for i in range(700)]
    else:
        lines = [row(0, "198.51.100.88", "10.0.0.30", 8443)]
    header = ("#fields\tts\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\n"
              "#types\ttime\taddr\tport\taddr\tport\tstring\n")
    with log.open("a", encoding="utf-8") as stream:
        if log.stat().st_size == 0:
            stream.write(header)
        stream.writelines(lines)
    return len(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description="Dry-run log simulation; sends no packets")
    parser.add_argument("kind", choices=("scan", "brute", "ddos", "anomaly"))
    parser.add_argument("--capture-dir", type=Path, required=True)
    args = parser.parse_args()
    print(f"Appended {simulate(args.kind, args.capture_dir)} synthetic {args.kind} log rows")


if __name__ == "__main__":
    main()
