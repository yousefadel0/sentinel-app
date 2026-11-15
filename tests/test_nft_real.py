"""Real-nftables validation (skipped unless root + nft + CAP_NET_ADMIN).

Run it where it can execute, e.g. in a privileged Linux container:
  docker run --rm --cap-add NET_ADMIN -v <repo>:/src <image-with-nftables> \
    sh -c "cd /src && pip install -q -e .[dev] && \
           python -m pytest tests/test_nft_real.py -o addopts= -q"
"""
from __future__ import annotations

import os
import shutil
import subprocess
import time

import pytest

from sentinel.actuators.nftables_local import NftablesLocalActuator
from sentinel.models import Action, ActionType
from sentinel.validator import Validator
from tests.fixtures.decision.helpers import config_view


def _can_run() -> bool:
    if shutil.which("nft") is None or not hasattr(os, "geteuid") or os.geteuid() != 0:
        return False
    p = subprocess.run(["nft", "add", "table", "ip", "sentinel_probe"],
                       capture_output=True, text=True)
    subprocess.run(["nft", "delete", "table", "ip", "sentinel_probe"],
                   capture_output=True, text=True)
    return p.returncode == 0


pytestmark = pytest.mark.skipif(not _can_run(), reason="needs root + nft + NET_ADMIN")
TABLE = "sentinel_realtest"


def _nft(*args):
    return subprocess.run(["nft", *args], capture_output=True, text=True).stdout


@pytest.fixture()
def act():
    a = NftablesLocalActuator(Validator(config_view()), table=TABLE)
    yield a
    subprocess.run(["nft", "delete", "table", "ip", TABLE], capture_output=True)


def blk(ip="203.0.113.9", ttl=30, t=ActionType.BLOCK_IP_TEMP):
    return Action(type=t, target_ip=ip, ttl_minutes=ttl, rationale="t")


def test_block_applies_with_kernel_timeout_and_rolls_back(act):
    r = act.execute(blk())
    assert r.ok, r.detail
    out = _nft("list", "set", "ip", TABLE, "blocked")
    assert "203.0.113.9" in out and "timeout 30m" in out
    chain = _nft("list", "chain", "ip", TABLE, "forward")
    assert "@blocked" in chain and "drop" in chain
    assert act.rollback(r.rollback_token).ok
    assert "203.0.113.9" not in _nft("list", "set", "ip", TABLE, "blocked")
    assert act.rollback(r.rollback_token).ok                  # idempotent


def test_ruleset_is_idempotent_and_flush_all_works_cross_process(act):
    assert act.execute(blk("203.0.113.1")).ok
    assert act.execute(blk("203.0.113.2", t=ActionType.THROTTLE_SRC)).ok
    assert act.execute(blk("203.0.113.3", t=ActionType.QUARANTINE_ASSET)).ok
    act2 = NftablesLocalActuator(Validator(config_view()), table=TABLE)
    assert act2.ensure_ruleset() is None
    chain = _nft("list", "chain", "ip", TABLE, "input")
    assert chain.count("ip saddr @blocked") == 1              # no duplicate rules
    assert act2.flush_all().ok
    for s in ("blocked", "throttled", "quarantined"):
        assert "203.0.113" not in _nft("list", "set", "ip", TABLE, s)


def test_element_expires_in_the_kernel_without_any_sweeper(act):
    assert act.execute(blk()).ok
    subprocess.run(["nft", "add", "element", "ip", TABLE, "blocked",
                    "{ 203.0.113.77 timeout 2s }"], check=True)
    assert "203.0.113.77" in _nft("list", "set", "ip", TABLE, "blocked")
    time.sleep(3)
    assert "203.0.113.77" not in _nft("list", "set", "ip", TABLE, "blocked")


def test_executor_to_real_kernel_end_to_end(tmp_path, act):
    """Approved decision -> Executor gates -> REAL nft element -> sweep
    rollback -> audit rows, plus the cross-process `ctl rollback --all`."""
    from sentinel.actuation import Executor
    from sentinel.auditstore.store import Store
    from sentinel.cli import main
    from sentinel.decision.chain import Facts
    from tests.fixtures.decision.helpers import FakeClock, IncidentStub, alert, engine

    eng, _ = engine(clock=FakeClock())
    d = eng.evaluate(IncidentStub([alert("auth_fail_burst", 0.93, crit="critical")]),
                     Facts(liveness="alive"))
    resolved = eng.resolve(d.incident_id, True)
    store = Store(tmp_path / "a.sqlite")
    now = [1000.0]
    ex = Executor(store=store, validator=Validator(config_view()),
                  actuators={"nftables_local": act}, autonomy_level=lambda: 1,
                  dry_run=False, clock=lambda: now[0],
                  liveness_check=lambda ctx: "alive")  # test sensor
    ctx = {"incident_id": d.incident_id, "src_ip": "198.51.100.7", "dst_ip": "10.0.0.99"}
    assert ex.handle(resolved, ctx, "approved") == "executed"
    assert "198.51.100.7" in _nft("list", "set", "ip", TABLE, "blocked")
    assert store.rows("actions")[0]["executed"] == 1
    now[0] += 31 * 60
    assert ex.sweep() == 1                                    # TTL rollback
    assert "198.51.100.7" not in _nft("list", "set", "ip", TABLE, "blocked")
    assert store.rows("rollbacks")[0]["ok"] == 1
    # a second block, then the operator panic button from a fresh process
    now[0] = 5000.0
    ctx2 = dict(ctx, src_ip="198.51.100.8")
    assert ex.handle(resolved, ctx2, "approved") == "executed"
    assert main(["ctl", "rollback", "--all", "--table", TABLE]) == 0
    assert "198.51.100.8" not in _nft("list", "set", "ip", TABLE, "blocked")
    assert store.verify_chain()["ok"]
    store.close()
