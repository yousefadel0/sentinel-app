"""Sentinel CLI — M0 surface exactly (operator decision, YAGNI):

  sentinel --config <path>              boot check: load+validate, exit 0/1
  sentinel ctl config validate <path>   explicit validation of a config file
  sentinel --version                    print version

Global flag --dry-run defaults TRUE (G2/P5); --no-dry-run opts out.
No future subcommands are stubbed here — later milestones add their own.
"""
from __future__ import annotations

import argparse
import os
import secrets
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

    learn = ctl_sub.add_parser("learning", help="inspect or control the learning period")
    learn.add_argument("path", metavar="PROFILE", help="path to learning.json")
    learn_sub = learn.add_subparsers(dest="learning_command", required=True)
    learn_sub.add_parser("status", help="print the versioned learning profile")
    mode = learn_sub.add_parser("mode", help="set auto, learning or active override")
    mode.add_argument("value", choices=("auto", "learning", "active"))
    extend = learn_sub.add_parser("extend", help="add days to the learning period")
    extend.add_argument("days", type=int)

    sub.add_parser("selftest", help="prove the pipeline works on this machine "
                   "(temporary folder, touches nothing)")

    ui = sub.add_parser(
        "ui", help="serve the Ops UI over an existing audit store (observer)")
    ui.add_argument("--store", metavar="SQLITE", default=None,
                    help="audit store (default: audit_store.path or "
                         "capture/audit.sqlite)")
    ui.add_argument("--capture-dir", default="capture", metavar="DIR")
    ui.add_argument("--report-dir", default="reports", metavar="DIR")
    ui.add_argument("--port", type=int, default=None,
                    help="override the port (must be in ops_ui.allowed_ports)")

    run = sub.add_parser(
        "run", help="live SHADOW daemon: tail sensor logs, decide, audit")
    run.add_argument("--capture-dir", required=True, metavar="DIR",
                     help="directory with Suricata eve.json and Zeek *.log")
    run.add_argument("--poll-interval", type=float, default=1.0,
                     help="seconds between polls (default: 1)")
    run.add_argument("--ui", action="store_true",
                     help="also serve the loopback Ops UI (needs ops_ui.enabled)")
    run.add_argument("--skip-history", action="store_true",
                     help="on first start ignore lines already in the logs")

    audit = ctl_sub.add_parser("audit", help="audit store integrity")
    audit_sub = audit.add_subparsers(dest="audit_command", required=True)
    ver = audit_sub.add_parser(
        "verify", help="recompute the tamper-evidence hash chain")
    ver.add_argument("path", metavar="SQLITE", help="audit store file")
    ver.add_argument("--expect-head", metavar="HASH", default=None,
                     help="externally anchored chain head (detects truncation)")

    usr = ctl_sub.add_parser("user", help="Ops UI accounts (accounts mode)")
    usr.add_argument("--db", default=None, metavar="SQLITE",
                     help="accounts database (default: from --config)")
    usr_sub = usr.add_subparsers(dest="user_command", required=True)
    u_add = usr_sub.add_parser("add", help="create a user (prompts for a password)")
    u_add.add_argument("username")
    u_add.add_argument("--role", required=True, choices=("viewer", "analyst", "admin"))
    u_add.add_argument("--password-stdin", action="store_true",
                       help="read the temporary password from stdin")
    usr_sub.add_parser("list", help="list users")
    for _name, _help in (("disable", "disable a user and end their sessions"),
                         ("enable", "re-enable a user"),
                         ("reset-mfa", "force MFA re-enrolment at next login")):
        usr_sub.add_parser(_name, help=_help).add_argument("username")
    u_role = usr_sub.add_parser("role", help="change a user's role")
    u_role.add_argument("username")
    u_role.add_argument("role", choices=("viewer", "analyst", "admin"))
    u_pw = usr_sub.add_parser("reset-password",
                              help="set a temporary password (must change at login)")
    u_pw.add_argument("username")
    u_pw.add_argument("--password-stdin", action="store_true")

    rb = ctl_sub.add_parser(
        "rollback", help="G3 one-command rollback of nftables enforcement")
    rb.add_argument("--all", action="store_true", required=True,
                    help="flush every Sentinel block/throttle/quarantine")
    rb.add_argument("--table", default="sentinel",
                    help="nft table name (default: sentinel)")

    intel = ctl_sub.add_parser("intel", help="read-only threat knowledge operations")
    intel_sub = intel.add_subparsers(dest="intel_command", required=True)
    sync = intel_sub.add_parser(
        "sync-attack", help="download official MITRE ATT&CK Enterprise STIX 2.1")
    sync.add_argument("--output", default="data/attack/enterprise-attack.json",
                      help="local cache path (default: data/attack/enterprise-attack.json)")

    return parser


def _read_password(from_stdin: bool) -> str:
    if from_stdin:
        return sys.stdin.readline().rstrip("\n")
    import getpass
    first = getpass.getpass("Temporary password (12+ chars): ")
    if getpass.getpass("Repeat: ") != first:
        raise ValueError("passwords do not match")
    return first


def _ctl_user(args) -> int:
    """Account administration from the server shell (first admin, recovery)."""
    import getpass
    from pathlib import Path as _Path

    from sentinel.ui.accounts import AccountError, AccountStore
    db, audit_path = args.db, None
    if args.config:
        try:
            cfg = load_config(args.config)
        except ConfigError as exc:
            print(f"invalid config: {exc}", file=sys.stderr)
            return EXIT_FAIL
        audit_path = (cfg.get("audit_store") or {}).get("path")
        db = db or (cfg.get("ops_ui") or {}).get("accounts_db") or (
            str(_Path(audit_path).parent / "accounts.sqlite") if audit_path else None)
    if not db:
        print("give --config (with audit_store.path) or --db", file=sys.stderr)
        return EXIT_FAIL
    accounts = AccountStore(db)
    actor = "cli:" + (getpass.getuser() or "unknown")
    try:
        cmd, target = args.user_command, getattr(args, "username", "")
        if cmd == "list":
            for u in accounts.list():
                print(f"{u.username:20} {u.role:8} mfa={'on' if u.mfa_enabled else 'off':3}"
                      f" {'DISABLED' if u.disabled else 'active':8} last_login={u.last_login or '-'}")
            return EXIT_OK
        if cmd == "add":
            accounts.create(target, args.role, _read_password(args.password_stdin))
            print(f"OK: created {target} ({args.role}). First login: change the "
                  "password and enrol the authenticator app.")
        elif cmd == "role":
            accounts.set_role(target, args.role)
            print(f"OK: {target} is now {args.role}")
        elif cmd in ("disable", "enable"):
            accounts.set_disabled(target, cmd == "disable")
            print(f"OK: {target} {cmd}d")
        elif cmd == "reset-mfa":
            accounts.reset_mfa(target)
            print(f"OK: {target} will enrol MFA again at next login")
        elif cmd == "reset-password":
            accounts.reset_password(target, _read_password(args.password_stdin))
            print(f"OK: temporary password set for {target}")
    except (AccountError, ValueError) as exc:
        print(f"refused: {exc}", file=sys.stderr)
        return EXIT_FAIL
    finally:
        accounts.close()
    if audit_path and _Path(audit_path).is_file():
        from sentinel.auditstore.store import Store
        store = Store(audit_path)
        try:
            store.record_action(case_id="auth", action_type=f"user_{cmd.replace('-', '_')}",
                                target_ip=None, ttl_minutes=None, verdict="ok",
                                executed=False, detail=f"user={actor} target={target}")
        finally:
            store.close()
    return EXIT_OK


def _port_is_free(host: str, port: int) -> bool:
    import socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        try:
            sock.bind((host, port))
        except OSError:
            return False
    return True


def _run_ui(args) -> int:
    """One-command Ops UI launcher with actionable errors for every common
    failure (missing extra, missing ops_ui block, no token, busy port)."""
    import os
    import secrets
    from pathlib import Path

    try:
        import fastapi  # noqa: F401
        import uvicorn  # noqa: F401
    except ImportError as exc:
        print(f"Ops UI dependencies are missing ({exc.name}).\n"
              'Install them with:  python -m pip install -e ".[ops-ui]"',
              file=sys.stderr)
        return EXIT_FAIL
    if not args.config:
        print("sentinel ui: --config is required, e.g.\n"
              "  python -m sentinel --config pilot_config.yaml ui",
              file=sys.stderr)
        return EXIT_FAIL
    try:
        cfg = load_config(args.config)
    except ConfigError as exc:
        print(f"REFUSING — invalid config {args.config} (ref §8):\n{exc}",
              file=sys.stderr)
        return EXIT_FAIL

    ui_cfg = dict(cfg.get("ops_ui") or {})
    if not ui_cfg:
        print("note: config has no ops_ui block; using the safe defaults "
              "(127.0.0.1:8080, token in SENTINEL_OPS_UI_TOKEN).")
    ui_cfg.setdefault("bind", "127.0.0.1:8080")
    ui_cfg.setdefault("auth_token_env", "SENTINEL_OPS_UI_TOKEN")
    ui_cfg.setdefault("allowed_ports", [8080])
    ui_cfg["enabled"] = True
    if args.port is not None:
        ui_cfg["bind"] = f"{ui_cfg['bind'].rsplit(':', 1)[0]}:{args.port}"
    cfg["ops_ui"] = ui_cfg

    env = ui_cfg["auth_token_env"]
    if ui_cfg.get("auth_mode") != "accounts" and not os.environ.get(env):
        os.environ[env] = secrets.token_urlsafe(24)
        print(f"{env} was not set, so a random token was generated for "
              f"THIS run only:\n  {os.environ[env]}\n"
              "Put exactly this value in your header rule "
              "(X-Sentinel-Token) or set the variable yourself next time.")

    host, _, port_txt = ui_cfg["bind"].rpartition(":")
    host = host.strip("[]")
    if not _port_is_free(host, int(port_txt)):
        print(f"Port {port_txt} on {host} is already in use — an old Ops UI "
              "is probably still running. Stop it (Ctrl+C in its window) or "
              "pass --port with another allowed port.", file=sys.stderr)
        return EXIT_FAIL

    from sentinel.auditstore.store import Store
    from sentinel.ui.app import create_app, serve

    store_path = (args.store or (cfg.get("audit_store") or {}).get("path")
                  or "capture/audit.sqlite")
    if not Path(store_path).is_file():
        print(f"Audit store not found: {store_path}\n"
              "Pass --store PATH, or run the pilot/daemon first so it is "
              "created.", file=sys.stderr)
        return EXIT_FAIL
    try:
        create_app(cfg)                       # validates bind/token up front
    except (RuntimeError, ValueError, ConfigError) as exc:
        print(f"Ops UI refused to start: {exc}", file=sys.stderr)
        return EXIT_FAIL
    store = Store(store_path, check_same_thread=False)
    print(f"Ops UI (observer mode, no engine) on http://{host}:{port_txt}/\n"
          f"  audit store : {store_path}\n"
          f"  send header : X-Sentinel-Token: <your token>\n"
          "  stop with Ctrl+C")
    try:
        serve(cfg, store=store, capture_dir=Path(args.capture_dir),
              report_dir=Path(args.report_dir))
    except KeyboardInterrupt:
        pass
    finally:
        store.close()
    return EXIT_OK


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
    if not getattr(args, "dry_run_explicit", False):
        args.dry_run = cfg.get("enforcement_dry_run", True)
    if not store_cfg.get("path"):
        print("sentinel run requires `audit_store.path` in the config (ref §8/D5)",
              file=sys.stderr)
        return EXIT_FAIL
    if not args.dry_run and int(cfg["autonomy_level"]) < 1:
        print("REFUSING --no-dry-run: autonomy_level is 0 (shadow). Raise it "
              "deliberately in the config once the evidence gate is met "
              "(Project.md §6); nothing would be executed at L0 anyway.",
              file=sys.stderr)
        return EXIT_FAIL
    if not args.dry_run and not cfg["site"].get("protected_ips"):
        print("REFUSING --no-dry-run: site.protected_ips is empty. Configure "
              "admin, gateway, DNS and critical-server addresses first.",
              file=sys.stderr)
        return EXIT_FAIL
    if args.ui:
        ui_cfg = cfg.get("ops_ui") or {}
        token_env = ui_cfg.get("auth_token_env", "SENTINEL_OPS_UI_TOKEN")
        if ui_cfg.get("auth_mode") != "accounts" and not os.environ.get(token_env):
            os.environ[token_env] = secrets.token_urlsafe(24)
            print(f"{token_env} for this run: {os.environ[token_env]}",
                  file=sys.stderr)
    store = Store(store_cfg["path"], check_same_thread=not args.ui)
    daemon = build_daemon(cfg, Path(args.capture_dir), store,
                          start_at_end=args.skip_history,
                          dry_run=args.dry_run,
                          learning_path=Path(store_cfg["path"]).with_name("learning.json"),
                          intel_path=Path(store_cfg["path"]).with_name("attack-catalog.json"),
                          cve_path=Path(store_cfg["path"]).with_name("cve-cache.json"))
    if not args.dry_run:
        log.warning("ENFORCEMENT_ENABLED", autonomy_level=cfg["autonomy_level"],
                    note="actions will be executed through configured actuators")
    if args.ui:
        from sentinel.ui.app import create_app, serve  # optional extra
        try:
            create_app(cfg)      # fail fast on disabled/unsafe UI config
        except RuntimeError as exc:
            store.close()
            print(f"sentinel run --ui refused: {exc}", file=sys.stderr)
            return EXIT_FAIL
        threading.Thread(
            target=serve, daemon=True, name="ops-ui",
            kwargs=dict(cfg=cfg, engine=daemon._engine, store=store,
                        capture_dir=Path(args.capture_dir),
                        on_resolved=daemon.execute_approved,
                        on_ack=daemon.acknowledge,
                        critical_status=daemon.critical_status,
                        executor=daemon._executor,
                        config_path=Path(args.config))).start()
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
    args.dry_run_explicit = any(flag in (argv if argv is not None else sys.argv[1:])
                                for flag in ("--dry-run", "--no-dry-run"))
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

    if args.command == "ctl" and args.ctl_command == "audit":
        import json as _json
        from pathlib import Path as _Path

        from sentinel.auditstore.store import Store
        if not _Path(args.path).is_file():
            print(f"no such audit store: {args.path}", file=sys.stderr)
            return EXIT_FAIL
        store = Store(args.path)
        try:
            report = store.verify_chain(args.expect_head)
        finally:
            store.close()
        print(_json.dumps(report, indent=2, sort_keys=True))
        return EXIT_OK if report["ok"] else EXIT_FAIL

    if args.command == "ctl" and args.ctl_command == "learning":
        import json as _json
        from pathlib import Path as _Path
        from sentinel.learning import LearningProfile
        if not _Path(args.path).is_file():
            print(f"no such learning profile: {args.path}", file=sys.stderr)
            return EXIT_FAIL
        try:
            profile = LearningProfile(args.path)
            if args.learning_command == "mode":
                profile.set_override(args.value)
            elif args.learning_command == "extend":
                profile.extend(args.days)
            print(_json.dumps(profile.export(), indent=2, sort_keys=True))
        except (OSError, ValueError, KeyError) as exc:
            print(f"learning profile error: {exc}", file=sys.stderr)
            return EXIT_FAIL
        return EXIT_OK

    if args.command == "ctl" and args.ctl_command == "user":
        return _ctl_user(args)

    if args.command == "ctl" and args.ctl_command == "rollback":
        from sentinel.actuators import NftablesLocalActuator
        res = NftablesLocalActuator(None, table=args.table).flush_all()
        print(("OK: " if res.ok else "FAILED: ") + res.detail)
        return EXIT_OK if res.ok else EXIT_FAIL

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

    if args.command == "ui":
        return _run_ui(args)

    if args.command == "selftest":
        from sentinel.selftest import main as _selftest
        return _selftest()

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
