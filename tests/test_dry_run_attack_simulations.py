"""One dry-run detector-to-policy simulation for every supported attack family."""
import random

import pytest

from sentinel.auditstore.store import Store
from sentinel.actuation import Executor
from sentinel.decision.chain import Facts
from sentinel.evaluation import harness as H
from sentinel.validator import Validator
from tests.fixtures.decision.helpers import IncidentStub, config_view, engine
from tests.test_executor import FakeActuator


@pytest.mark.parametrize("generator,signal", [
    (H.scan, "scan"),
    (H.brute, "auth_fail_burst"),
    (H.ddos, "volume_spike"),
    (H.beacon, "beacon_periodic"),
    (H.dns_tunnel, "dns_tunneling"),
])
def test_attack_family_detects_and_records_dry_run_decision(
        tmp_path, generator, signal):
    scenario = generator(random.Random(21))
    alerts = H.run_scenario(scenario)
    hits = [a for a in alerts if signal in a.signals]
    assert hits, scenario.name

    decision_engine, _ = engine()
    decision = decision_engine.evaluate(IncidentStub(hits[:1]),
                                        Facts(liveness="alive"))
    store = Store(tmp_path / "audit.sqlite")
    rec = decision.recommendation
    store.record_decision(
        case_id="dry_run_simulation", incident_id=decision.incident_id,
        outcome=decision.outcome.value, score=decision.score,
        base_score=decision.base_score, tier=decision.tier,
        cap_applied=decision.cap_applied, would=decision.would,
        recommendation=rec.__dict__ if rec else {},
        audit_events=[e.__dict__ for e in decision.audit_events])
    actuator = FakeActuator("nftables_local")
    upstream = FakeActuator("webhook_soar")
    executor = Executor(store=store, validator=Validator(config_view()),
                        actuators={"nftables_local": actuator,
                                   "webhook_soar": upstream},
                        autonomy_level=lambda: 2, dry_run=True,
                        liveness_check=lambda ctx: "alive")
    source = "auto"
    if decision.outcome.value in ("human_approval", "report_wait"):
        decision = decision_engine.resolve(decision.incident_id, True,
                                           actor="simulation")
        source = "approved"
    verdict = executor.handle(decision, {"incident_id": decision.incident_id,
                                         "src_ip": hits[0].src_ip,
                                         "dst_ip": hits[0].dst_ip}, source)
    assert verdict in (None, "dry_run")
    assert store.rows("decisions")[0]["case_id"] == "dry_run_simulation"
    assert not actuator.calls and not upstream.calls
    assert all(row["executed"] == 0 for row in store.rows("actions"))
    assert store.verify_chain()["ok"]
    store.close()
