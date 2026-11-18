"""GATE (c): both ABCs documented and importable.

Proves: package-root imports work; docstrings exist and are substantive;
abstract enforcement actually blocks incomplete implementations; the Alert
model carries the exact §4 field set.
"""
from __future__ import annotations

import inspect

import pytest

from sentinel.contracts import Actuator, DataSource          # gate (c): importable
from sentinel.models import (
    Action,
    ActionResult,
    ActionType,
    Alert,
    AlertMeta,
    AssetHint,
    ConfidenceTier,
    SourceRef,
)


# ---------- importability & documentation ----------

def test_datasource_importable_and_documented():
    assert inspect.isabstract(DataSource)
    assert DataSource.fetch.__doc__ and DataSource.fetch.__doc__.strip()
    assert DataSource.health.__doc__ and DataSource.health.__doc__.strip()
    class_doc = DataSource.__doc__ or ""
    for token in ("fetch()", "health()", "healthy", "degraded", "down",
                  "heartbeat_ts", "packet_drops", "coverage_percent"):
        assert token in class_doc + (DataSource.health.__doc__ or ""), (
            f"DataSource contract docs missing {token!r}"
        )


def test_actuator_importable_and_documented():
    assert inspect.isabstract(Actuator)
    assert Actuator.execute.__doc__ and Actuator.execute.__doc__.strip()
    assert Actuator.rollback.__doc__ and Actuator.rollback.__doc__.strip()
    class_doc = Actuator.__doc__ or ""
    for token in ("execute(action)", "rollback(token)", "ActionResult",
                  "dry-run", "TTL <= 60"):
        assert token in class_doc, f"Actuator contract docs missing {token!r}"


# ---------- abstract enforcement ----------

def test_incomplete_datasource_cannot_instantiate():
    class Half(DataSource):
        def fetch(self):  # health() not implemented
            return []

    with pytest.raises(TypeError):
        Half()


def test_abstract_method_bodies_refuse_direct_call():
    """Calling an unimplemented ABC method raises NotImplementedError."""

    class Bare(DataSource):
        name = "bare"

        def fetch(self):
            return DataSource.fetch(self)

        def health(self):
            return DataSource.health(self)

    src = Bare()
    with pytest.raises(NotImplementedError):
        src.fetch()
    with pytest.raises(NotImplementedError):
        src.health()

    class BareAct(Actuator):
        name = "bare_act"

        def execute(self, action: Action) -> ActionResult:
            return Actuator.execute(self, action)

        def rollback(self, token: str) -> ActionResult:
            return Actuator.rollback(self, token)

    act = BareAct()
    with pytest.raises(NotImplementedError):
        act.execute(Action(type=ActionType.NOTIFY_ONLY))
    with pytest.raises(NotImplementedError):
        act.rollback("t-0")


def test_complete_concrete_implementations_work():
    class OkSource(DataSource):
        name = "fixture_source"

        def fetch(self):
            return [_alert()]

        def health(self):
            return {"status": "healthy", "heartbeat_ts": None,
                    "packet_drops": 0, "coverage_percent": 100.0,
                    "last_alert_ts": None}

    class OkActuator(Actuator):
        name = "fixture_actuator"

        def execute(self, action: Action) -> ActionResult:
            return ActionResult(ok=True, actuator=self.name,
                                detail="simulated", rollback_token="t-1")

        def rollback(self, token: str) -> ActionResult:
            return ActionResult(ok=True, actuator=self.name,
                                detail=f"rolled back {token}")

    src = OkSource()
    act = OkActuator()
    assert [a.alert_id for a in src.fetch()] == ["a-0001"]
    assert src.health()["status"] == "healthy"
    result = act.execute(Action(type=ActionType.NOTIFY_ONLY))
    assert result.ok and result.rollback_token == "t-1"
    assert act.rollback("t-1").ok


# ---------- §4 Alert model field coverage ----------

def _alert() -> Alert:
    return Alert(
        alert_id="a-0001",
        ts="2026-10-20T12:00:00Z",
        source=SourceRef(adapter="eve_json", ref="eve.json:L42"),
        src_ip="203.0.113.7",
        dst_ip="10.0.0.4",
        src_port=44444,
        dst_port=22,
        protocol="tcp",
        vlan="prod",
        asset_hint=AssetHint(resolved_hostname="dc-01", asset_id="asset-1",
                             criticality="critical"),
        signals=("scan",),
        confidence_raw=0.93,
        confidence_tier=ConfidenceTier.A,
        meta=AlertMeta(packet_count=900, byte_count=45000,
                       duration_seconds=12.5,
                       raw_payload_hash="deadbeef" * 8),
    )


def test_alert_carries_exact_section4_fields():
    a = _alert()
    d = a.to_dict()
    for key in ("alert_id", "ts", "source", "src_ip", "dst_ip", "src_port",
                "dst_port", "protocol", "vlan", "asset_hint", "signals",
                "confidence_raw", "confidence_tier", "meta"):
        assert key in d, f"§4 field missing from Alert: {key}"
    assert {"adapter", "ref"} <= set(d["source"])
    assert {"resolved_hostname", "asset_id", "criticality"} == set(d["asset_hint"])
    assert {"packet_count", "byte_count", "duration_seconds",
            "raw_payload_hash", "label"} == set(d["meta"])


def test_confidence_bounds_and_tiers_enforced():
    with pytest.raises(ValueError):
        Alert(**{**_alert().__dict__, "confidence_raw": 1.5})
    # plain-string tier coerces to enum
    coerced = Alert(**{**_alert().__dict__, "confidence_tier": "B"})
    assert coerced.confidence_tier is ConfidenceTier.B


def test_evidence_digest_is_stable_sha256():
    a1, a2 = _alert(), _alert()
    assert a1.evidence_digest() == a2.evidence_digest()
    assert len(a1.evidence_digest()) == 64


def test_action_types_match_allowed_actions_v1():
    allowed = {m.value for m in ActionType}
    assert allowed == {
        "notify_only", "throttle_src", "block_ip_temp",
        "quarantine_asset", "escalate_human",
    }
