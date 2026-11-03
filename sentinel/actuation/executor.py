"""Executor — the ONLY path from a Decision to a real actuator.

Everything that could make Sentinel touch a network is gated here, in order:

1. the decision must carry an enforceable recommendation;
2. the autonomy ladder (§6): auto outcomes need L2+, human-approved ones L1+;
   at L0 (shadow) nothing is ever executed;
3. dry-run (G2/P5, the DEFAULT): the intent is recorded, nothing is executed;
4. the §3.1 validator (G6) with the engine's own verdict as a fact;
5. an hourly cap on top of the engine's rate limiter (approvals bypass it);
6. an actuator must exist and be healthy — otherwise an honest failure.

Every branch writes an ``actions`` row (verdict + detail), so "why did / didn't
Sentinel act" is always answerable from the audit store (P6). Enforcement is
temporary by construction (G3): kernel-side expiry for nftables plus an
in-process sweeper that rolls back anything past its TTL.
"""
from __future__ import annotations

import threading
import time
from collections import deque
from typing import Any, Callable, Optional

from sentinel.logging_setup import get_logger
from sentinel.models import Action, ActionType
from sentinel.validator import ValidationError, ValidationVerdict, Validator

log = get_logger("sentinel.actuation")

_NOOP = frozenset({"notify_only", "escalate_human"})
_UPSTREAM = "recommend_upstream_mitigation"
DEFAULT_TTL_MINUTES = 30

#: verdicts written to ``actions.verdict``
V_EXECUTED = "executed"
V_FAILED = "failed"
V_DRY_RUN = "dry_run"
V_WITHHELD = "withheld_autonomy"
V_REJECTED = "rejected_g6"
V_NO_ACTUATOR = "no_actuator"
V_RATE = "rate_limited"


class Executor:
    def __init__(self, *, store, validator: Validator,
                 actuators: dict[str, Any], autonomy_level: Callable[[], int],
                 dry_run: bool = True, max_per_hour: int = 20,
                 clock: Callable[[], float] = time.time) -> None:
        self._store = store
        self._validator = validator
        self._actuators = dict(actuators)
        self._level = autonomy_level
        self.dry_run = bool(dry_run)
        self._max_per_hour = int(max_per_hour)
        self._clock = clock
        self._lock = threading.RLock()
        self._active: dict[tuple[str, str], dict] = {}   # (action, ip) -> info
        self._sent: deque = deque()
        self.executed = 0

    # -- public ---------------------------------------------------------- #

    def handle(self, decision, ctx: dict, source: str,
               case_id: str = "live") -> Optional[str]:
        """Consider ONE decision for enforcement. ``source`` is ``"auto"``
        (straight from the engine) or ``"approved"`` (a human said yes).
        Returns the recorded verdict, or None when there was nothing to do."""
        rec = decision.recommendation
        if rec is None or rec.action in _NOOP:
            return None
        outcome = decision.outcome.value
        if source == "auto" and outcome not in ("auto_act", "auto_throttle"):
            return None
        if source in ("approved", "deadline") and outcome != "auto_act":
            return None                       # denied/timed out => notify only
        with self._lock:
            return self._handle(decision, ctx, source, rec, outcome, case_id)

    def sweep(self) -> int:
        """Roll back anything past its TTL. Returns how many were rolled back."""
        n = 0
        now = self._clock()
        with self._lock:
            for key, info in list(self._active.items()):
                if now < info["expires"]:
                    continue
                self._active.pop(key, None)
                act = self._actuators.get(info["actuator"])
                if act is None or not info.get("token"):
                    continue
                res = act.rollback(info["token"])
                self._store.record_rollback(case_id=info["case_id"],
                                            token=info["token"], ok=bool(res.ok),
                                            detail=f"ttl expiry: {res.detail}")
                n += 1
        return n

    def rollback_all(self) -> int:
        """Operator panic button: undo everything this process enforced."""
        n = 0
        with self._lock:
            for key, info in list(self._active.items()):
                self._active.pop(key, None)
                act = self._actuators.get(info["actuator"])
                if act is not None and info.get("token"):
                    res = act.rollback(info["token"])
                    self._store.record_rollback(case_id=info["case_id"],
                                                token=info["token"],
                                                ok=bool(res.ok),
                                                detail=f"rollback_all: {res.detail}")
                    n += 1
        return n

    def active(self) -> list[dict]:
        with self._lock:
            return [dict(v, action=k[0], target=k[1])
                    for k, v in self._active.items()]

    # -- internals ------------------------------------------------------- #

    def _record(self, case_id, action, target, ttl, verdict, executed, detail):
        self._store.record_action(
            case_id=case_id, action_type=action, target_ip=target,
            ttl_minutes=ttl, verdict=verdict, executed=executed, detail=detail)
        return verdict

    def _handle(self, decision, ctx, source, rec, outcome, case_id):
        action_name = rec.action
        target = self._target(rec, ctx)
        ttl = int(rec.params.get("ttl_minutes") or DEFAULT_TTL_MINUTES)
        ttl = max(1, min(ttl, 60))                                   # G3
        incident = ctx.get("incident_id", decision.incident_id)
        tag = f"{source}:{incident}"

        need = 2 if source in ("auto", "deadline") else 1
        level = int(self._level())
        if level < need:
            return self._record(
                case_id, action_name, target, ttl, V_WITHHELD, False,
                f"{tag}: autonomy L{level} < L{need} required for "
                f"{source} execution; recommendation only")
        if self.dry_run:
            return self._record(
                case_id, action_name, target, ttl, V_DRY_RUN, False,
                f"{tag}: dry-run (G2) — would run {action_name} on {target}")

        if (action_name, str(target)) in self._active:
            return None                                       # already enforced

        try:
            atype = ActionType(action_name)
        except ValueError:
            atype = None
        if atype is None and action_name != _UPSTREAM:
            return self._record(case_id, action_name, target, ttl, V_REJECTED,
                                False, f"{tag}: unknown action {action_name!r}")

        now = self._clock()
        while self._sent and now - self._sent[0] > 3600:
            self._sent.popleft()
        if len(self._sent) >= self._max_per_hour:
            return self._record(case_id, action_name, target, ttl, V_RATE, False,
                                f"{tag}: hourly enforcement cap {self._max_per_hour}")

        name = "webhook_soar" if action_name == _UPSTREAM else "nftables_local"
        actuator = self._actuators.get(name)
        if actuator is None:
            return self._record(case_id, action_name, target, ttl, V_NO_ACTUATOR,
                                False, f"{tag}: no {name} actuator configured")

        act = Action(type=atype or ActionType.NOTIFY_ONLY, target_ip=target,
                     ttl_minutes=ttl, rationale=rec.because,
                     params=dict(rec.params))
        try:
            verdict = self._validator.validate(
                act, facts={"engine_outcome": outcome, "liveness": "alive"})
        except ValidationError as exc:
            return self._record(case_id, action_name, target, ttl, V_REJECTED,
                                False, f"{tag}: {exc}")
        if verdict is not ValidationVerdict.APPROVED:
            return self._record(case_id, action_name, target, ttl, V_REJECTED,
                                False, f"{tag}: §3.1 chain rejected (G6)")

        try:
            if action_name == _UPSTREAM:
                res = actuator.execute_upstream(
                    action_name=action_name, target_ip=str(target),
                    ttl_minutes=ttl, rationale=rec.because,
                    incident_id=incident,
                    audit_events=[{"name": e.name, "detail": e.detail}
                                  for e in decision.audit_events])
            else:
                res = actuator.execute(act)
        except Exception as exc:                  # an actuator bug must not crash the loop
            return self._record(case_id, action_name, target, ttl, V_FAILED,
                                False, f"{tag}: actuator raised {type(exc).__name__}")
        if not res.ok:
            return self._record(case_id, action_name, target, ttl, V_FAILED,
                                False, f"{tag}: {res.detail}")
        self._sent.append(now)
        self.executed += 1
        self._active[(action_name, str(target))] = {
            "actuator": name, "token": res.rollback_token,
            "expires": now + ttl * 60, "case_id": case_id, "incident_id": incident}
        log.info("action_executed", action=action_name, target=target,
                 ttl_minutes=ttl, incident_id=incident, source=source)
        return self._record(case_id, action_name, target, ttl, V_EXECUTED, True,
                            f"{tag}: {res.detail}")

    @staticmethod
    def _target(rec, ctx) -> Optional[str]:
        want = rec.params.get("target")
        if rec.action == _UPSTREAM:
            return ctx.get("dst_ip")              # the victim under attack
        if want == "dst":
            return ctx.get("dst_ip")
        return ctx.get("src_ip")                  # block/throttle the source
