"""M4 — nftables_local actuator tests (honesty probe, TTL defense, rollback)."""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sentinel.models import Action, ActionResult, ActionType  # noqa: E402
from sentinel.actuators.nftables_local import NftablesLocalActuator  # noqa: E402
from sentinel.validator import Validator, ValidationVerdict  # noqa: E402
from tests.fixtures.decision.helpers import config_view  # noqa: E402


class FakeRunner:
    """Scripted subprocess runner — no real nft in CI."""

    def __init__(self, rc=0, stdout="", stderr=""):
        self.rc = rc
        self.stdout = stdout
        self.stderr = stderr
        self.calls = []

    def __call__(self, cmd, **kw):
        self.calls.append(cmd)
        return subprocess.CompletedProcess(cmd, self.rc, self.stdout, self.stderr)


class ScriptedRunner:
    """Probe succeeds; real nft operations fail with a given rc."""

    def __init__(self, op_rc=2, op_stderr="syntax error"):
        self.op_rc = op_rc
        self.op_stderr = op_stderr
        self.calls = []

    def __call__(self, cmd, **kw):
        self.calls.append(cmd)
        probe = "list" in cmd
        from subprocess import CompletedProcess
        return CompletedProcess(
            cmd, 0 if probe else self.op_rc,
            "" if probe else "", "" if probe else self.op_stderr)


def block(ttl=30, target="203.0.113.9", atype=ActionType.BLOCK_IP_TEMP,
          **params):
    return Action(type=atype, target_ip=target, ttl_minutes=ttl,
                  rationale="t", params=params)


# --------------------------------------------------------------------- #
def test_health_down_when_nft_absent(monkeypatch):
    """Sandbox honesty: absent binary ⇒ health=down, NEVER fake success."""
    monkeypatch.setattr("shutil.which", lambda _: None)
    act = NftablesLocalActuator(Validator(config_view()))
    h = act.health()
    assert h["status"] == "down" and "not found" in h["detail"]

    got = act.execute(block())
    assert got.ok is False and "honest failure" in got.detail


def test_health_healthy_when_probe_succeeds():
    runner = FakeRunner(rc=0, stdout="table ip sentinel {}\n")
    act = NftablesLocalActuator(Validator(config_view()), runner=runner,
                                which_fn=lambda _: "/usr/sbin/nft")
    assert act.health()["status"] == "healthy"


def test_ttl_over_60_rejected_AT_actuator_even_if_caller_passes_it():
    """Binding 4: engine cap NOT trusted at enforcement layer."""
    act = NftablesLocalActuator(
        Validator(config_view()),
        runner=FakeRunner(rc=0), which_fn=lambda _: "/usr/sbin/nft")
    got = act.execute(block(ttl=90))          # caller smuggles ttl>60
    assert got.ok is False
    assert "REJECTED ttl_minutes=90 > 60" in got.detail
    assert not act.pending_expiry()           # nothing was applied


def test_execute_success_creates_temp_rule_with_timeout():
    runner = FakeRunner(rc=0)
    act = NftablesLocalActuator(Validator(config_view()), runner=runner,
                                which_fn=lambda _: "/usr/sbin/nft")
    got = act.execute(block(ttl=30))
    assert got.ok is True and got.rollback_token
    cmd = runner.calls[-1]
    assert cmd[:3] == ["nft", "add", "rule"]
    assert "timeout" in cmd and "1800s" in cmd       # 30m ⇒ kernel timer
    assert act.pending_expiry() == [got.rollback_token]


def test_throttle_rule_carries_rate_pps():
    runner = FakeRunner(rc=0)
    act = NftablesLocalActuator(Validator(config_view()), runner=runner,
                                which_fn=lambda _: "/usr/sbin/nft")
    got = act.execute(block(atype=ActionType.THROTTLE_SRC, rate_pps=250))
    assert got.ok is True
    assert "limit rate 250/second" in " ".join(runner.calls[-1])


def test_g6_rejection_inside_actuator_blocks_nft_call():
    v = Validator(config_view(critical_assets=frozenset({"203.0.113.9"})))
    runner = FakeRunner(rc=0)
    act = NftablesLocalActuator(v, runner=runner,
                                which_fn=lambda _: "/usr/sbin/nft")
    got = act.execute(block(target="203.0.113.9"))
    assert got.ok is False and "G6 rejected" in got.detail
    assert runner.calls == []                 # no nft invocation at all


def test_rollback_removes_rule_and_is_idempotent():
    runner = FakeRunner(rc=0)
    act = NftablesLocalActuator(Validator(config_view()), runner=runner,
                                which_fn=lambda _: "/usr/sbin/nft")
    tok = act.execute(block()).rollback_token
    rb = act.rollback(tok)
    assert rb.ok is True and "rolled back" in rb.detail
    again = act.rollback(tok)                 # idempotent quiet success
    assert again.ok is True and "already rolled back" in again.detail
    assert act.pending_expiry() == []


def test_nft_add_failure_returns_honest_error():
    runner = ScriptedRunner(op_rc=2, op_stderr="syntax error at 'x'")
    act = NftablesLocalActuator(Validator(config_view()), runner=runner,
                                which_fn=lambda _: "/usr/sbin/nft")
    got = act.execute(block())
    # probe was healthy; the ADD itself failed — honest rc surfaced
    assert got.ok is False and "nft add failed rc=2" in got.detail
    adds = [c for c in runner.calls if "add" in c]
    probes = [c for c in runner.calls if "list" in c]
    assert len(adds) == 1 and len(probes) >= 1
