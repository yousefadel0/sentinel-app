"""M4 — webhook_soar actuator tests (schema gate, bounded retry, degrade)."""
from __future__ import annotations

import sys
from pathlib import Path
import urllib.error

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sentinel.models import Action, ActionType  # noqa: E402
from sentinel.actuators.webhook_soar import (  # noqa: E402
    MAX_ATTEMPTS,
    WebhookSoarActuator,
)
from sentinel.validator import Validator  # noqa: E402
from tests.fixtures.decision.helpers import config_view  # noqa: E402


class Flushing:
    """Minimal context-manager response."""

    def __init__(self, status):
        self.status = status

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def block():
    return Action(type=ActionType.BLOCK_IP_TEMP, target_ip="203.0.113.9",
                  ttl_minutes=30, rationale="t")


def offline_urlopen(req, timeout=None):
    raise urllib.error.URLError("connection refused")


# --------------------------------------------------------------------- #
def test_offline_degrades_to_log_only_no_crash():
    """Binding 3: network down ⇒ ok=False + log_only note; never raises."""
    sleeps = []
    act = WebhookSoarActuator(
        Validator(config_view()), "http://soar.invalid/hook",
        urlopen=offline_urlopen, sleeper=sleeps.append)
    got = act.execute(block(), incident_id="inc-1")
    assert got.ok is False and got.actuator == "webhook_soar"
    assert "log_only degradation" in got.detail
    assert len(sleeps) == MAX_ATTEMPTS - 1     # bounded backoff, not infinite


def test_bounded_retry_then_success_on_third_attempt():
    calls = {"n": 0}

    def flaky(req, timeout=None):
        calls["n"] += 1
        if calls["n"] < 3:
            raise urllib.error.URLError("timeout")
        return Flushing(200)

    sleeps = []
    act = WebhookSoarActuator(
        Validator(config_view()), "http://soar.local/hook",
        urlopen=flaky, sleeper=sleeps.append)
    got = act.execute(block(), incident_id="inc-2")
    assert got.ok is True and "HTTP 200" in got.detail
    assert calls["n"] == 3 and len(sleeps) == 2   # budget respected


def test_payload_schema_rejected_before_network():
    class NeverCalled:
        def __call__(self, *a, **kw):      # network must NEVER be touched
            raise AssertionError("network reached despite invalid payload")

    act = WebhookSoarActuator(
        Validator(config_view()), "http://soar.local/hook",
        urlopen=NeverCalled())
    bad = Action(type=ActionType.BLOCK_IP_TEMP, target_ip=None,
                 ttl_minutes=30, rationale="t")     # aggressive w/o target_ip
    got = act.execute(bad, incident_id="inc-3")
    assert got.ok is False and "payload schema rejected" in got.detail


def test_g6_rejection_blocks_post():
    v = Validator(config_view(critical_assets=frozenset({"203.0.113.9"})))
    class NeverCalled:
        def __call__(self, *a, **kw):
            raise AssertionError("POST reached despite G6 rejection")

    act = WebhookSoarActuator(v, "http://soar.local/hook", urlopen=NeverCalled())
    got = act.execute(block(), incident_id="inc-4")
    assert got.ok is False and "G6 rejected" in got.detail


def test_rollback_is_quiet_noop():
    act = WebhookSoarActuator(Validator(config_view()),
                              "http://soar.local/hook",
                              urlopen=offline_urlopen)
    rb = act.rollback("whatever")
    assert rb.ok is True and "no rollback handle" in rb.detail
