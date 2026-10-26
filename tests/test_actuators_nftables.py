"""M4 — nftables_local actuator tests (honesty probe, TTL defense, rollback).

Command shapes here were validated against REAL nftables in
tests/test_nft_real.py; this file covers the logic with a scripted runner.
"""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sentinel.models import Action, ActionType  # noqa: E402
from sentinel.actuators.nftables_local import NftablesLocalActuator  # noqa: E402
from sentinel.validator import Validator  # noqa: E402
from tests.fixtures.decision.helpers import config_view  # noqa: E402

NFT = "/usr/sbin/nft"


class FakeRunner:
    """Scripted subprocess runner — no real nft here."""

    def __init__(self, rc=0, stdout="", stderr=""):
        self.rc, self.stdout, self.stderr = rc, stdout, stderr
        self.calls = []

    def __call__(self, cmd, **kw):
        self.calls.append(cmd)
        return subprocess.CompletedProcess(cmd, self.rc, self.stdout, self.stderr)


def block(ttl=30, target="203.0.113.9", atype=ActionType.BLOCK_IP_TEMP, **params):
    return Action(type=atype, target_ip=target, ttl_minutes=ttl,
                  rationale="t", params=params)


def make(runner=None, **kw):
    return NftablesLocalActuator(Validator(config_view(**kw.pop("cv", {}))),
                                 runner=runner or FakeRunner(),
                                 which_fn=lambda _: NFT, **kw)


def _elem_cmds(runner):
    return [c for c in runner.calls if "element" in c]


# --------------------------------------------------------------------- #
def test_health_down_when_nft_absent():
    """Sandbox honesty: absent binary => health=down, NEVER fake success."""
    act = NftablesLocalActuator(Validator(config_view()), which_fn=lambda _: None)
    h = act.health()
    assert h["status"] == "down" and "not found" in h["detail"]
    got = act.execute(block())
    assert got.ok is False and "honest failure" in got.detail


def test_health_healthy_when_probe_succeeds():
    assert make(FakeRunner(stdout="table ip sentinel {}\n")).health()["status"] == "healthy"


def test_ttl_over_60_rejected_AT_actuator_even_if_caller_passes_it():
    """Binding 4: engine cap NOT trusted at enforcement layer."""
    act = make()
    got = act.execute(block(ttl=90))
    assert got.ok is False and "REJECTED ttl_minutes=90 > 60" in got.detail
    assert not act.pending_expiry()


def test_execute_success_adds_set_element_with_kernel_timeout():
    runner = FakeRunner()
    act = make(runner)
    got = act.execute(block(ttl=30))
    assert got.ok is True and got.rollback_token == "blocked:203.0.113.9"
    cmd = _elem_cmds(runner)[-1]
    assert cmd[1:6] == ["add", "element", "ip", "sentinel", "blocked"]
    assert cmd[-1] == "{ 203.0.113.9 timeout 30m }"
    assert act.pending_expiry() == [got.rollback_token]


def test_ruleset_created_once_before_first_element():
    runner = FakeRunner()
    act = make(runner)
    act.execute(block())
    first_elem = next(i for i, c in enumerate(runner.calls) if "element" in c)
    assert any("table" in c for c in runner.calls[:first_elem])
    n = len(runner.calls)
    act.execute(block(target="203.0.113.10"))
    assert len(runner.calls) - n <= 2                  # probe + element only


def test_throttle_goes_to_throttled_set():
    runner = FakeRunner()
    act = make(runner, throttle_pps=250)
    got = act.execute(block(atype=ActionType.THROTTLE_SRC))
    assert got.ok and got.rollback_token.startswith("throttled:")
    assert any("limit rate over 250/second" in " ".join(c) for c in runner.calls)


def test_g6_rejection_inside_actuator_blocks_nft_call():
    runner = FakeRunner()
    act = make(runner, cv={"critical_assets": frozenset({"203.0.113.9"})})
    got = act.execute(block(target="203.0.113.9"))
    assert got.ok is False and "G6 rejected" in got.detail
    assert runner.calls == []


def test_never_enforces_against_special_or_invalid_addresses():
    runner = FakeRunner()
    act = make(runner)
    for bad in ("127.0.0.1", "0.0.0.0", "224.0.0.1", "169.254.1.1",
                "not-an-ip", "1.2.3.4; flush ruleset", "::1"):
        assert act.execute(block(target=bad)).ok is False, bad
    assert not _elem_cmds(runner)


def test_rollback_deletes_element_and_is_idempotent():
    class R(FakeRunner):
        def __call__(self, cmd, **kw):
            self.calls.append(cmd)
            if "delete" in cmd and len([c for c in self.calls if "delete" in c]) > 1:
                return subprocess.CompletedProcess(
                    cmd, 1, "", "Error: Could not process rule: No such file or directory")
            return subprocess.CompletedProcess(cmd, 0, "", "")

    runner = R()
    act = make(runner)
    tok = act.execute(block()).rollback_token
    rb = act.rollback(tok)
    assert rb.ok is True and rb.detail == "rolled back"
    assert [c for c in runner.calls if "delete" in c][0][-1] == "{ 203.0.113.9 }"
    again = act.rollback(tok)
    assert again.ok is True and "already rolled back" in again.detail
    assert act.pending_expiry() == []
    assert act.rollback("evil:1.2.3.4").ok is False
    assert act.rollback("blocked:not-an-ip").ok is False


def test_nft_element_failure_returns_honest_error():
    class R(FakeRunner):
        def __call__(self, cmd, **kw):
            self.calls.append(cmd)
            if "element" in cmd:
                return subprocess.CompletedProcess(cmd, 2, "", "syntax error at 'x'")
            return subprocess.CompletedProcess(cmd, 0, "", "")

    act = make(R())
    got = act.execute(block())
    assert got.ok is False and "nft add failed rc=2" in got.detail
    assert act.pending_expiry() == []


def test_setup_failure_is_reported_not_swallowed():
    class R(FakeRunner):
        def __call__(self, cmd, **kw):
            self.calls.append(cmd)
            if "list" in cmd and "tables" in cmd:
                return subprocess.CompletedProcess(cmd, 0, "", "")
            return subprocess.CompletedProcess(cmd, 1, "", "Operation not permitted")

    got = make(R()).execute(block())
    assert got.ok is False and "nft setup failed" in got.detail


def test_flush_all_flushes_three_sets():
    runner = FakeRunner()
    assert make(runner).flush_all().ok
    assert [c[-1] for c in runner.calls if "flush" in c] == [
        "blocked", "throttled", "quarantined"]
