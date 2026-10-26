"""Sentinel CLI — M0 surface exactly (operator decision, YAGNI):

  sentinel --config <path>              boot check: load+validate, exit 0/1
  sentinel ctl config validate <path>   explicit validation of a config file
  sentinel --version                    print version

Global flag --dry-run defaults TRUE (G2/P5); --no-dry-run opts out.
No future subcommands are stubbed here — later milestones add their own.
"""
from __future__ import annotations

import argparse
import sys

import sentinel
from sentinel.config import ConfigError, load_config
from sentinel.logging_setup import get_logger, setup_logging
from sentinel.threatintel.attack import sync_attack_catalog

log = get_logger("sentinel.cli")

EXIT_OK = 0
EXIT_FAIL = 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="sentinel",
        description="Sentinel — autonomous AI network defense appliance",
    )
    parser.add_argument("--version", action="version",
                        version=f"sentinel {sentinel.__version__}")
    # G2: dry-run DEFAULT everywhere; live needs explicit opt-out.
    dry = parser.add_mutually_exclusive_group()
    dry.add_argument("--dry-run", dest="dry_run", action="store_true", default=True,
                     help="simulate actions, never touch the network (default: True)")
    dry.add_argument("--no-dry-run", dest="dry_run", action="store_false",
                     help="enable live enforcement (explicit opt-in required)")

    parser.add_argument("--config", metavar="PATH",
                        help="path to config.yaml; boot check loads+validates it")
    parser.add_argument("--log-level", default="INFO",
                        choices=["DEBUG", "INFO", "WARNING", "ERROR"])

    sub = parser.add_subparsers(dest="command")

    ctl = sub.add_parser("ctl", help="operator control commands")
    ctl_sub = ctl.add_subparsers(dest="ctl_command", required=True)
    cfg = ctl_sub.add_parser("config", help="config operations")
    cfg_sub = cfg.add_subparsers(dest="config_command", required=True)
    val = cfg_sub.add_parser("validate", help="strictly validate a config file")
    val.add_argument("path", metavar="PATH", help="path to config.yaml")

    run = sub.add_parser(
        "run", help="live SHADOW daemon: tail sensor logs, decide, audit")
    run.add_argument("--capture-dir", required=True, metavar="DIR",
                     help="directory with Suricata eve.json and Zeek *.log")
    run.add_argument("--poll-interval", type=float, default=1.0,
                     help="seconds between polls (default: 1)")
    run.add_argument("--skip-history", action="store_true",
                     help="on first start ignore lines already in the logs")

    intel = ctl_sub.add_parser("intel", help="read-only threat knowledge operations")
    intel_sub = intel.add_subparsers(dest="intel_command", required=True)
    sync = intel_sub.add_parser(
        "sync-attack", help="download official MITRE ATT&CK Enterprise STIX 2.1")
    sync.add_argument("--output", default="data/attack/enterprise-attack.json",
                      help="local cache path (default: data/attack/enterprise-attack.json)")

    return parser


def _run_daemon(args) -> int:
    import signal
    import threading
    from pathlib import Path

    from sentinel.auditstore.store import Store
    from sentinel.daemon import build_daemon

    if not args.config:
        print("sentinel run: --config is required", file=sys.stderr)
        return EXIT_FAIL
    try:
        cfg = load_config(args.config)
    except ConfigError as exc:
        print(f"REFUSING BOOT — invalid config {args.config} (ref §8):\n{exc}",
              file=sys.stderr)
        return EXIT_FAIL
    store_cfg = cfg.get("audit_store") or {}
    if not store_cfg.get("path"):
        print("sentinel run requires `audit_store.path` in the config (ref §8/D5)",
              file=sys.stderr)
        return EXIT_FAIL
    if not args.dry_run:
        # The live loop is shadow-only until an actuation milestone ships.
        log.warning("no_dry_run_ignored", reason="live daemon is shadow-only")
    store = Store(store_cfg["path"])
    daemon = build_daemon(cfg, Path(args.capture_dir), store,
                          start_at_end=args.skip_history)
    stop = threading.Event()
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, lambda *_: stop.set())
    try:
        daemon.run(stop, args.poll_interval)
    finally:
        store.close()
    return EXIT_OK


def main(argv: list[str] | None = None) -> int:
    """Entry point. Returns process exit code (0 ok / 1 fail)."""
    args = build_parser().parse_args(argv)
    setup_logging(args.log_level)

    if args.command == "ctl" and args.ctl_command == "config":
        try:
            load_config(args.path)
        except ConfigError as exc:
            log.error("config_validation_failed", path=args.path,
                      error=str(exc), ref="§8")
            print(f"INVALID config {args.path} — refusing (ref §8):\n{exc}",
                  file=sys.stderr)
            return EXIT_FAIL
        log.info("config_valid", path=args.path, dry_run=args.dry_run)
        print(f"OK: config {args.path} is valid (ref §8)")
        return EXIT_OK

    if args.command == "ctl" and args.ctl_command == "intel":
        try:
            result = sync_attack_catalog(args.output)
        except Exception as exc:
            log.error("attack_catalog_sync_failed", error=str(exc))
            print(f"ATT&CK catalog sync failed: {exc}", file=sys.stderr)
            return EXIT_FAIL
        print(f"OK: cached {result['techniques']} ATT&CK techniques at {result['path']}")
        return EXIT_OK

    if args.command == "run":
        return _run_daemon(args)

    # Boot check mode: --config given -> load+validate, report, exit 0/1.
    if args.config:
        try:
            load_config(args.config)
        except ConfigError as exc:
            log.error("boot_refused_invalid_config", path=args.config,
                      error=str(exc), ref="§8")
            print(f"REFUSING BOOT — invalid config {args.config} (ref §8):\n{exc}",
                  file=sys.stderr)
            return EXIT_FAIL
        log.info("boot_check_passed", path=args.config,
                 dry_run=args.dry_run, version=sentinel.__version__)
        print(f"OK: boot check passed for {args.config} "
              f"(dry_run={args.dry_run}, v{sentinel.__version__})")
        return EXIT_OK

    # No --config and no ctl command: show usage rather than guessing (P5).
    build_parser().print_help()
    return EXIT_OK


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
