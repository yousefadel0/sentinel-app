"""DecisionEngine (§6): deterministic, table-driven, DRY-RUN ONLY.

Pipeline per evaluate():
  base score -> pre_band §3.1 rows (score-only) -> clamp (D1) -> band
  -> tier CAP (D2: C never auto-acts; B auto-throttles in the auto band —
     a Tier-B block becomes throttle_src, clarification 1)
  -> post_band §3.1 rows in table order (outcome/action only; first firing
     override wins, every fired row still emits its audit event, P6)
  -> playbook recommendation with explicit 'because'.

No wall-clock reads anywhere (clarification 2): approval deadlines come from
the injected clock at evaluation time (= now + APPROVAL_WINDOW_S) and
resolve() compares against the same clock. Engine state (rate windows,
pending approvals) is in-memory and deterministic (D3). The engine NEVER
invents liveness/NAT facts — absence is a fact pattern (Q4).
"""
from __future__ import annotations

import itertools
from dataclasses import dataclass, replace
from datetime import datetime, timedelta
from typing import Any, Iterable, Protocol

from sentinel.decision.chain import CHAIN_ROWS, Facts, Phase
from sentinel.decision.models import (
    APPROVAL_WINDOW_S,
    AttackType,
    AuditEvent,
    Decision,
    Outcome,
    Recommendation,
    SIGNAL_TO_ATTACK,
)
from sentinel.decision.playbooks import recommend
from sentinel.decision.rate_limiter import RateLimiter
from sentinel.decision.scoring import (
    CRITICALITY_WEIGHTS,
    SEVERITY_DEFAULTS,
    apply_penalties,
    band as band_of,
    base_score,
)

AGGRESSIVE_ACTIONS = frozenset({"block_ip_temp", "quarantine_asset"})


class Clock(Protocol):
    """Injected clock — anything callable returning an aware datetime."""

    def __call__(self) -> datetime: ...  # noqa: D105


@dataclass(frozen=True)
class ConfigView:
    """Read-only projection of already-validated §8 config (M0 loader)."""

    critical_assets: frozenset[str]
    monitored_vlans: frozenset[str]
    asymmetric_risk: str            # high | medium | low
    max_blocks_per_min: int
    max_blocks_per_hour: int
    autonomy_level: int
    auto_threshold: float = 0.90     # unit-test default; configs pass policy
    human_threshold: float = 0.80
    report_threshold: float = 0.50
    approval_window_s: int = APPROVAL_WINDOW_S
    report_window_s: int = 1800
    critical_min_score: float = 2.0  # > 1.0 = no critical class (default off)
    critical_window_s: int = APPROVAL_WINDOW_S
    protected_ips: frozenset[str] = frozenset()
    report_fallback_actions: tuple[str, ...] = ("throttle_src",)


class _IncidentLike(Protocol):
    """Structural type: correlator.Incident satisfies this."""

    incident_id: str
    alerts: Iterable[Any]
    dst_ip: str


def _weakest_tier(letters: Iterable[str]) -> str:
    """Weakest evidence wins the cap (P5 protective bias): C > B > A."""
    return max(letters)


class DecisionEngine:
    """Evaluates incidents into Decisions. Never touches a network."""

    def __init__(
        self,
        config_view: ConfigView,
        clock: Clock,
        rate_limiter: RateLimiter,
        controller: Any,   # AutonomyController; loose typing avoids a cycle
    ) -> None:
        self._cfg = config_view
        self._clock = clock
        self._limiter = rate_limiter
        self._controller = controller
        self._pending: dict[str, Decision] = {}
        self._ids = itertools.count(1)

    # ------------------------------------------------------------------ #
    def _band(self, score: float) -> str:
        if score >= self._cfg.auto_threshold:
            return "auto"
        if score >= self._cfg.human_threshold:
            return "human"
        if self._cfg.report_threshold and score >= self._cfg.report_threshold:
            return "report"
        return "log_only"

    @staticmethod
    def _g1_target(incident, attack_type: AttackType) -> str:
        """G1 judges the TARGET OF THE ACTION, not the victim: blocking a
        brute-force attacker targets the source address; quarantining for C2
        targets the destination. Falls back to dst when src is unknown."""
        from sentinel.decision.playbooks import PLAYBOOKS
        want = PLAYBOOKS[attack_type.value][1].get("target")
        src = getattr(incident, "src_ip", None)
        if want == "src" and src:
            return src
        return incident.dst_ip

    # ------------------------------------------------------------------ #
    #: Adapters whose alerts are ATTACK EVIDENCE (raw flow records are not).
    EVIDENCE_ADAPTERS = frozenset({"eve_json", "behavioral", "wazuh_inbound",
                                   "zeek_notice"})

    @classmethod
    def _combined_confidence(cls, alerts) -> tuple[float, dict]:
        """Strongest single source, boosted when INDEPENDENT sources agree.

        Per evidence adapter the best alert wins; with two or more adapters
        the result is noisy-OR (1 - prod(1 - c)), never below the strongest
        one and capped at 0.99. A single adapter keeps the old max() rule.
        """
        from sentinel.capture.confidence import noisy_or
        per: dict[str, float] = {}
        for a in alerts:
            name = a.source.adapter
            if name in cls.EVIDENCE_ADAPTERS:
                per[name] = max(per.get(name, 0.0), a.confidence_raw)
        overall = max(a.confidence_raw for a in alerts)
        if len(per) >= 2:
            overall = max(overall, noisy_or(list(per.values())))
        return min(0.99, overall) if len(per) >= 2 else overall, per

    # ------------------------------------------------------------------ #
    def _incident_inputs(
        self,
        incident: _IncidentLike,
        severity_override: int | None,
    ) -> tuple[float, str, int, str, AttackType]:
        """Derive (confidence, criticality, severity, tier, attack_type).

        Protective biases (documented, P5):
          confidence  = MAX over member alerts (worst-case story strength)
          criticality = heaviest weight over members' asset hints (Q3)
          tier        = WEAKEST member tier — one weak source caps the story
        Severity: explicit override first (phase-2 SIEM enrichment seam),
        else SEVERITY_DEFAULTS for the derived attack type.
        """
        alerts = list(incident.alerts)
        if not alerts:
            raise ValueError("incident has no alerts")
        confidence, conf_by_source = self._combined_confidence(alerts)
        self._last_conf_sources = conf_by_source
        criticality = max(
            ((a.asset_hint.criticality or "low") for a in alerts),
            key=lambda c: CRITICALITY_WEIGHTS[c],
        )
        tier = _weakest_tier(a.confidence_tier.value for a in alerts)
        signals = {s for a in alerts for s in a.signals}
        attack_type = AttackType.SCAN
        for signal_name, atype in SIGNAL_TO_ATTACK:
            if signal_name in signals:
                attack_type = atype
                break
        severity = severity_override or SEVERITY_DEFAULTS[attack_type.value]
        return confidence, criticality, severity, tier, attack_type

    # ------------------------------------------------------------------ #
    def _run_pre_band(
        self, facts: Facts,
    ) -> tuple[list[float], list[AuditEvent], set[str]]:
        """Evaluate pre_band rows ONCE each — score deltas + their events.

        Returns (deltas, events, fired_row_names); the names feed the
        post-band pass so a single row's outcome_override applies exactly
        once (no double-apply).
        """
        deltas: list[float] = []
        events: list[AuditEvent] = []
        fired_rows: set[str] = set()
        for row in CHAIN_ROWS:
            if row.phase is not Phase.PRE_BAND:
                continue
            fired = (
                (row.name == "nat_fallback"
                 and facts.nat_resolved_src is None
                 and facts.src_private_outside_local)
                or
                (row.name == "vlan_blind_spot" and not facts.vlan_monitored)
            )
            if fired:
                fired_rows.add(row.name)
                if row.penalty_delta is not None:
                    deltas.append(row.penalty_delta)
                    events.append(AuditEvent(row.audit_name, row.detail))
        return deltas, events, fired_rows

    # ------------------------------------------------------------------ #
    def _run_post_band(
        self,
        facts: Facts,
        dst_ip: str,
        original_action: str,
        current_action: str,
        outcome_now: Outcome,
        fired_pre: set[str],
    ) -> tuple[Outcome, str, list[AuditEvent], str | None]:
        """Apply §3.1 effects post-band, in table order, ONCE per row.

        Pre_band rows contribute ONLY their outcome_override here (their
        score delta already landed pre-band); post_band rows run their full
        predicate. First firing override wins; every fired row emits its
        audit event regardless (P6). G1 judges the ORIGINAL playbook action
        so no earlier cap can sneak an aggressive touch on an allowlisted
        asset. Asymmetric downgrades the ACTION only
        (block_ip_temp->throttle_src).
        Returns (outcome, action, events, cap_row_name_or_None).
        """
        final_outcome = outcome_now
        final_action = current_action
        override_taken = False
        cap: str | None = None
        events: list[AuditEvent] = []
        now = self._clock()
        for row in CHAIN_ROWS:
            if row.phase is not Phase.POST_BAND and row.name not in fired_pre:
                continue
            if row.phase is Phase.PRE_BAND:
                # single-row rule: its delta + event already landed pre-band;
                # here it contributes ONLY the outcome_override (no re-emit).
                if row.outcome_override is not None and not override_taken:
                    final_outcome = Outcome(row.outcome_override)
                    override_taken = True
                    cap = row.name
                continue
            audit_name: str | None = None
            override: str | None = None
            downgrade: str | None = None
            detail = row.detail
            if row.name == "liveness":
                if facts.liveness == "alive":
                    continue
                if facts.dry_run_simulation and facts.liveness == "unknown":
                    events.append(AuditEvent("dry_run_liveness_unverified",
                                             "recommendation only; no live-flow proof"))
                    continue
                audit_name = (
                    "stale_session_drift"
                    if facts.liveness == "stale"
                    else "liveness_unknown_treated_stale"  # Q4 verbatim split
                )
                override = "log_only"
            elif row.name == "critical_assets":
                if dst_ip not in (self._cfg.critical_assets |
                                  self._cfg.protected_ips) or \
                        original_action not in AGGRESSIVE_ACTIONS:
                    continue
                audit_name = row.audit_name   # critical_asset_allowlist_hit
                override = "escalate_human"
            elif row.name == "rate_limit":
                if final_action not in AGGRESSIVE_ACTIONS or \
                        not self._limiter.would_breach(now):
                    continue
                audit_name = row.audit_name   # rate_limit_breach_alarm
                detail = f"{row.detail}: {self._limiter.breach_reason(now)}"
                override = "notify_only"
            elif row.name == "asymmetric":
                if self._cfg.asymmetric_risk != "high" or \
                        final_action != "block_ip_temp":
                    continue
                audit_name = row.audit_name   # asymmetric_routing_risk
                downgrade = "throttle_src"
            events.append(AuditEvent(audit_name or row.audit_name, detail))
            if override is not None and not override_taken:
                final_outcome = Outcome(override)
                override_taken = True
                cap = row.name
            if downgrade is not None:
                final_action = downgrade
        return final_outcome, final_action, events, cap

    # ------------------------------------------------------------------ #
    def _build_recommendation(
        self,
        attack_type: AttackType,
        outcome: Outcome,
        action: str,
        cap: str | None,
    ) -> tuple[Recommendation | None, str]:
        """Playbook lookup + dry-run 'would do X because Y' phrase (P6)."""
        base_rec = recommend(attack_type)
        if outcome is Outcome.LOG_ONLY:
            return None, (
                f"would log only because confidence fell below the "
                f"{self._cfg.human_threshold:.2f} band; "
                f"playbook {base_rec.action} not proposed"
            )
        if outcome is Outcome.NOTIFY_ONLY:
            reason = cap or "chain downgrade"
            rec = Recommendation(
                action="notify_only",
                params={},
                because=f"downgraded from {base_rec.action} ({reason}); "
                        f"{base_rec.because}",
            )
        else:
            params = dict(base_rec.params)
            if action != base_rec.action:
                params.pop("target", None)   # throttle_src targets src flow
            rec = Recommendation(action=action, params=params,
                                 because=base_rec.because)
        verb = {
            Outcome.AUTO_ACT: "would auto-act",
            Outcome.AUTO_THROTTLE: "would auto-throttle",
            Outcome.HUMAN_APPROVAL: "would act after human approval",
            Outcome.REPORT_WAIT: "would report and wait for human",
            Outcome.ESCALATE_HUMAN: "would escalate to human",
            Outcome.NOTIFY_ONLY: "would notify only",
        }[outcome]
        suffix = f" [cap: {cap}]" if cap else ""
        return rec, f"{verb} {rec.action} because {rec.because}{suffix}"

    # ------------------------------------------------------------------ #
    def evaluate(
        self,
        incident: _IncidentLike,
        facts: Facts | None = None,
        severity_override: int | None = None,
    ) -> Decision:
        """Score, band, cap and chain one incident — DRY-RUN recommendation."""
        facts = facts or Facts()
        conf, crit, sev, tier, attack_type = self._incident_inputs(
            incident, severity_override)
        base = base_score(conf, crit, sev)

        if facts.vlan_monitored is None:
            # §3.1 step-3 predicate derived from real data (never invented):
            # every tagged member vlan must be in monitored_vlans.
            vlans = {a.vlan for a in incident.alerts if a.vlan is not None}
            facts = replace(
                facts,
                vlan_monitored=all(v in self._cfg.monitored_vlans
                                   for v in vlans))
        deltas, pre_events, fired_pre = self._run_pre_band(facts)
        score = apply_penalties(base, deltas)          # D1: clamp BEFORE banding
        banded = self._band(conf)

        outcome = {
            "auto": Outcome.AUTO_ACT,
            "human": Outcome.HUMAN_APPROVAL,
            "report": Outcome.REPORT_WAIT,
            "log_only": Outcome.LOG_ONLY,
        }[banded]

        playbook_action = recommend(attack_type).action
        action = playbook_action
        cap_applied: str | None = None

        # ---- tier caps (D2 + clarification 1) --------------------------- #
        cap_event: AuditEvent | None = None
        if tier == "C" and outcome in (Outcome.AUTO_ACT, Outcome.AUTO_THROTTLE):
            outcome = Outcome.NOTIFY_ONLY
            cap_applied = "tier_c_never_auto_act"
            cap_event = AuditEvent(cap_applied,
                                   "Tier C is never auto-acted (§3)")
        elif tier == "B" and outcome is Outcome.AUTO_ACT:
            outcome = Outcome.AUTO_THROTTLE
            cap_applied = "tier_b_throttle_cap"
            cap_event = AuditEvent(cap_applied,
                                   "Tier B auto-throttles; block becomes "
                                   "throttle_src (clarification 1)")
            if action == "block_ip_temp":
                action = "throttle_src"

        # ---- §3.1 post-band chain --------------------------------------- #
        chained_outcome, action, post_events, chain_cap = self._run_post_band(
            facts, self._g1_target(incident, attack_type), playbook_action,
            action, outcome,
            fired_pre)
        if chain_cap is not None:
            cap_applied = chain_cap

        events = (*pre_events,
                  *([cap_event] if cap_event else []),
                  *post_events)

        # ---- G4 budget bookkeeping for would-be auto blocks ------------- #
        now = self._clock()
        if chained_outcome is Outcome.AUTO_ACT and \
                action in AGGRESSIVE_ACTIONS:
            self._limiter.record_block(now)

        recommendation, would = self._build_recommendation(
            attack_type, chained_outcome, action, cap_applied)

        deadline = None
        is_critical = (chained_outcome is Outcome.HUMAN_APPROVAL
                       and score >= self._cfg.critical_min_score)
        if chained_outcome in (Outcome.HUMAN_APPROVAL, Outcome.REPORT_WAIT):
            window = (self._cfg.report_window_s
                      if chained_outcome is Outcome.REPORT_WAIT else
                      self._cfg.critical_window_s if is_critical
                      else self._cfg.approval_window_s)
            deadline = now + timedelta(seconds=window)

        decision = Decision(
            incident_id=incident.incident_id,
            outcome=chained_outcome,
            base_score=base,
            score=score,
            tier=tier,
            cap_applied=cap_applied,
            audit_events=events,
            recommendation=recommendation,
            approval_deadline=deadline,
            would=would,
            inputs={
                "confidence": round(conf, 4),
                "confidence_sources": {k: round(v, 4) for k, v in
                                       getattr(self, "_last_conf_sources", {}).items()},
                "criticality": crit, "severity": sev,
                "attack_type": attack_type.value,
                "penalties": [round(d, 3) for d in deltas],
                "critical": bool(is_critical),
                "approval_deadline": deadline.isoformat() if deadline else None,
                "fallback_actions": (list(self._cfg.report_fallback_actions)
                                     if chained_outcome is Outcome.REPORT_WAIT else []),
                "liveness": facts.liveness,
                "dry_run_simulation": facts.dry_run_simulation,
            },
        )
        if chained_outcome in (Outcome.HUMAN_APPROVAL, Outcome.REPORT_WAIT):
            self._pending[incident.incident_id] = decision
        return decision

    # ------------------------------------------------------------------ #
    def pending_approvals(self) -> dict[str, "Decision"]:
        """Read-only snapshot of pending human approvals (M7 ops UI surface).

        Returns a COPY keyed by approval id (= incident_id); mutation-safe
        against concurrent resolve(). The M7 UI renders this queue and its
        approve/deny routes call resolve() below — the SAME seam as CLI.
        """
        return dict(self._pending)

    def restore_pending(self, decision: Decision) -> None:
        """Restore an audited, unresolved approval after process restart."""
        if decision.outcome not in (Outcome.HUMAN_APPROVAL, Outcome.REPORT_WAIT):
            raise ValueError("only pending human decisions can be restored")
        if decision.approval_deadline is None:
            raise ValueError("pending decision has no deadline")
        self._pending[decision.incident_id] = decision

    def resolve(self, approval_id: str, approved: bool, *,
                by_deadline: bool = False, actor: str = "unspecified",
                action_override: str | None = None,
                ttl_minutes: int | None = None) -> Decision:
        """Resolve a pending human approval against the INJECTED clock.

        After the 15-minute window the verdict degrades to notify_only with
        audit event "human_approval_timeout" (Q5 verbatim). Within the
        window: approved -> auto_act recorded ("human_approval_granted");
        denied -> notify_only ("human_approval_denied").
        """
        if action_override is not None:
            allowed = {"notify_only", "throttle_src", "block_ip_temp",
                       "quarantine_asset"}
            if by_deadline or not approved or action_override not in allowed:
                raise ValueError("invalid approval action override")
            if ttl_minutes is not None and (type(ttl_minutes) is not int or
                                            not 1 <= ttl_minutes <= 60):
                raise ValueError("ttl_minutes must be 1..60")
        try:
            original = self._pending.pop(approval_id)
        except KeyError:
            raise KeyError(f"no pending approval {approval_id!r}") from None
        now = self._clock()
        assert original.approval_deadline is not None  # invariant of creation
        if by_deadline and original.tier == "C":
            # Tier C is never eligible for unattended action, even when a
            # human-approval decision reaches the critical deadline.
            outcome, event_name = (Outcome.NOTIFY_ONLY,
                                   "critical_deadline_tier_c_no_auto")
        elif by_deadline and original.outcome is Outcome.REPORT_WAIT:
            outcome, event_name = (Outcome.AUTO_THROTTLE,
                                   "report_deadline_safe_plan")
        elif by_deadline:
            # Critical-incident deadline reached with nobody acting: the
            # caller (escalation.CriticalWatch) takes responsibility; every
            # downstream gate (validator, G1, TTL, caps) still applies.
            outcome, event_name = Outcome.AUTO_ACT, "critical_deadline_auto_action"
        elif now > original.approval_deadline:
            outcome, event_name = Outcome.NOTIFY_ONLY, "human_approval_timeout"
        elif approved:
            outcome, event_name = Outcome.AUTO_ACT, "human_approval_granted"
        else:
            outcome, event_name = Outcome.NOTIFY_ONLY, "human_approval_denied"
        events = (*original.audit_events,
                  AuditEvent(event_name, f"resolved at {now.isoformat()} by {actor}"))
        rec = original.recommendation
        if event_name == "report_deadline_safe_plan":
            rec = Recommendation(action=self._cfg.report_fallback_actions[0],
                                 params={"target": "src", "ttl_minutes": 15},
                                 because="preconfigured bounded fallback after report deadline")
        elif outcome is Outcome.NOTIFY_ONLY or rec is None:
            rec = Recommendation(
                action="notify_only", params={},
                because=f"approval {event_name}; "
                        f"{rec.because if rec else 'no playbook action'}")
        elif action_override is not None:
            rec = Recommendation(
                action=action_override,
                params=({"target": "dst" if action_override == "quarantine_asset" else "src",
                         "ttl_minutes": ttl_minutes or 15}
                        if action_override != "notify_only" else {}),
                because=f"modified by {actor} from {rec.action}")
        return Decision(
            incident_id=original.incident_id,
            outcome=outcome,
            base_score=original.base_score,
            score=original.score,
            tier=original.tier,
            cap_applied=original.cap_applied,
            audit_events=events,
            recommendation=rec,
            approval_deadline=None,
            would=f"decision after approval: {outcome.value} — {rec.because}",
            inputs={**original.inputs, "approved_by": actor,
                    "modified_action": action_override,
                    "fallback_actions": (list(self._cfg.report_fallback_actions)
                                         if event_name == "report_deadline_safe_plan" else [])},
        )
