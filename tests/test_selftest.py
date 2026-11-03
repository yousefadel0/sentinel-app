"""`sentinel selftest` must pass on a healthy install and touch nothing."""
from __future__ import annotations

from sentinel.cli import main
from sentinel.selftest import run


def test_selftest_all_checks_pass():
    results = run()
    failed = [(n, d) for n, ok, d in results if not ok]
    assert not failed, failed
    assert len(results) >= 12


def test_selftest_cli_exit_code_and_output(capsys):
    assert main(["selftest"]) == 0
    out = capsys.readouterr().out
    assert "ALL" in out and "CHECKS PASSED" in out and "FAIL" not in out
