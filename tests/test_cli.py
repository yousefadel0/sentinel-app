"""GATE (b): --dry-run is default TRUE; CLI exit semantics.

Also covers the exact M0 CLI surface: boot check via --config,
`ctl config validate`, and `--version`.
"""
from __future__ import annotations

import json
import sys

import pytest

from sentinel import __version__
from sentinel.cli import build_parser, main


# ---------- gate (b): dry-run defaults TRUE ----------

def test_dry_run_defaults_true_no_flags():
    args = build_parser().parse_args([])
    assert args.dry_run is True


def test_dry_run_defaults_true_even_with_config():
    args = build_parser().parse_args(["--config", "/tmp/whatever.yaml"])
    assert args.dry_run is True


def test_explicit_no_dry_run_flips_flag():
    args = build_parser().parse_args(["--no-dry-run"])
    assert args.dry_run is False


def test_explicit_dry_run_stays_true():
    args = build_parser().parse_args(["--dry-run"])
    assert args.dry_run is True


# ---------- boot check (--config) ----------

def test_boot_check_valid_config_exits_zero(valid_config_path, capsys):
    assert main(["--config", str(valid_config_path)]) == 0
    out = capsys.readouterr().out
    assert "boot check passed" in out
    assert "dry_run=True" in out          # default visible in output


def test_boot_check_invalid_config_refuses_exit_one(invalid_dir, capsys):
    rc = main(["--config", str(invalid_dir / "unknown_top_key.yaml")])
    captured = capsys.readouterr()
    assert rc == 1
    assert "REFUSING BOOT" in captured.err
    assert "(ref §8)" in captured.err


def test_boot_check_missing_file_exits_one(tmp_path, capsys):
    rc = main(["--config", str(tmp_path / "absent.yaml")])
    captured = capsys.readouterr()
    assert rc == 1
    assert "not found" in captured.err


# ---------- ctl config validate ----------

def test_ctl_validate_valid_config_exits_zero(valid_config_path, capsys):
    rc = main(["ctl", "config", "validate", str(valid_config_path)])
    assert rc == 0
    assert "is valid" in capsys.readouterr().out


def test_ctl_validate_invalid_config_exits_one(invalid_dir, capsys):
    rc = main(["ctl", "config", "validate",
               str(invalid_dir / "bad_enum_value.yaml")])
    captured = capsys.readouterr()
    assert rc == 1
    assert "INVALID config" in captured.err
    assert "(ref §8)" in captured.err


# ---------- --version ----------

def test_version_flag_prints_version(capsys):
    with pytest.raises(SystemExit) as excinfo:
        main(["--version"])
    assert excinfo.value.code == 0
    assert __version__ in capsys.readouterr().out


# ---------- python -m sentinel entry ----------

def test_dunder_main_module_runs_boot_check(valid_config_path):
    import subprocess
    import sys

    proc = subprocess.run(
        [sys.executable, "-m", "sentinel", "--config", str(valid_config_path)],
        capture_output=True, text=True,
    )
    assert proc.returncode == 0
    assert "boot check passed" in proc.stdout


# ---------- no-arg invocation shows help (P5: never guess) ----------

def test_no_args_prints_help_exits_zero(capsys):
    assert main([]) == 0
    assert "usage:" in capsys.readouterr().out


# ---------- structured JSON logging (§8) ----------

def test_log_lines_are_json():
    import logging

    from sentinel.logging_setup import JsonFormatter

    record = logging.LogRecord(
        "sentinel.test", logging.INFO, __file__, 1,
        "hello_world", (), None,
    )
    record.key = "value"
    record.count = 3

    payload = json.loads(JsonFormatter().format(record))
    assert payload["event"] == "hello_world"
    assert payload["key"] == "value"
    assert payload["count"] == 3
    assert payload["level"] == "info"


def test_json_logger_merges_kwargs_into_record(caplog):
    import logging

    from sentinel.logging_setup import get_logger

    caplog.set_level(logging.DEBUG)
    log = get_logger("sentinel.test")
    log.info("boot_check_passed", path="/tmp/c.yaml", dry_run=True)

    record = caplog.records[-1]
    assert record.getMessage() == "boot_check_passed"
    assert record.path == "/tmp/c.yaml"
    assert record.dry_run is True


def test_json_logger_warning_error_levels_and_exc_formatting():
    import logging

    from sentinel.logging_setup import JsonFormatter, get_logger

    log = get_logger("sentinel.test.levels")
    log.warning("watch_it", code=42)
    log.error("boom", detail="disk full")

    root = logging.getLogger("sentinel.test.levels")
    records = [r for r in root.records] if hasattr(root, "records") else []
    # fallback: exercise formatter directly with synthetic records
    rec_w = logging.LogRecord("sentinel.test.levels", logging.WARNING,
                              __file__, 1, "watch_it", (), None)
    rec_w.code = 42
    payload = json.loads(JsonFormatter().format(rec_w))
    assert payload["level"] == "warning" and payload["code"] == 42

    try:
        raise RuntimeError("simulated failure")
    except RuntimeError:
        rec_e = logging.LogRecord("sentinel.test.levels", logging.ERROR,
                                  __file__, 1, "boom", (), sys.exc_info())
    rendered = JsonFormatter().format(rec_e)
    payload = json.loads(rendered)
    assert payload["event"] == "boom"
    assert "RuntimeError" in payload["exc"]
