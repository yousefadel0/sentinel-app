"""Critical-incident escalation with a deadline.

A *critical* incident is a human-approval decision whose score reached
``critical_response.min_score``. For those the engine sets the approval window
to ``deadline_minutes`` (instead of the usual 15). This module then:

1. sends an URGENT message to every notifier — what happened, what is needed,
   WHEN time runs out, and what Sentinel will do on its own at that moment;
2. repeats the reminder every ``reminder_minutes`` until someone acts;
3. stops if an engineer approves, denies or acknowledges ("I'm on it");
4. at the deadline, if nobody did and ``auto_remediate_on_timeout`` is on,
   resolves the approval itself through ``Engine.resolve(by_deadline=True)``
   and hands the result to the Executor with source ``deadline`` — so every
   normal gate still applies (autonomy L2, dry-run, validator/G1, TTL <= 60,
   hourly cap) and every step is audited.

Never auto-acted here: decisions that are already ``escalate_human`` (G1 —
the action's target is a protected critical asset, or a blind-spot VLAN).
Those get the urgent message and stay human-only; G1 has no exceptions.
"""
from __future__ import annotations

from dataclasses import dataclass
from dataclasses import replace
from datetime import datetime
from typing import Callable, Optional

from sentinel.logging_setup import get_logger
from sentinel.notify.hub import Notification

log = get_logger("sentinel.escalation")


@dataclass
class _Case:
    ctx: dict
    deadline: datetime
    opened: datetime
    next_reminder: datetime
    acked_by: Optional[str] = None
    reminders: int = 0


def _fmt_clock(dt: datetime) -> str:
    return dt.astimezone().strftime("%H:%M")


class CriticalWatch:
    def __init__(self, *, store, engine, hub=None, executor=None,
                 clock: Callable[[], datetime], auto_remediate: bool = True,
                 reminder_s: int = 300, record_decision=None) -> None:
        self._store, self._engine = store, engine
        self._hub, self._executor = hub, executor
        self._clock = clock
        self._auto = bool(auto_remediate)
        self._reminder_s = int(reminder_s)
        self._record_decision = record_decision      # daemon._record
        self._open: dict[str, _Case] = {}
        self.auto_actions = 0

    # -- intake ----------------------------------------------------------- #

    def consider(self, decision, ctx: dict) -> bool:
        """Open an escalation if ``decision`` is critical. True if opened."""
        if decision.outcome.value not in ("human_approval", "report_wait"):
            return False
        deadline = decision.approval_deadline
        if deadline is None or decision.incident_id in self._open:
            return False
        now = self._clock()
        from datetime import timedelta
        case = _Case(ctx=dict(ctx), deadline=deadline, opened=now,
                     next_reminder=now + timedelta(seconds=self._reminder_s))
        self._open[decision.incident_id] = case
        self._audit(decision.incident_id, "critical_escalation_opened",
                    f"deadline {deadline.isoformat()}; auto={self._auto}")
        self._send(decision, case, first=True)
        return True

    # -- engineer actions ------------------------------------------------------ #

    def ack(self, incident_id: str, actor: str) -> bool:
        """'I'm handling it' — cancels the automatic action, keeps the clock."""
        case = self._open.get(incident_id)
        if case is None or case.acked_by:
            return False
        case.acked_by = actor
        self._audit(incident_id, "critical_acknowledged", f"by {actor}")
        return True

    def resolved(self, incident_id: str) -> None:
        """A human approved/denied: the escalation is over."""
        if self._open.pop(incident_id, None) is not None:
            self._audit(incident_id, "critical_escalation_closed",
                        "resolved by a human")

    def status(self, incident_id: str) -> Optional[dict]:
        case = self._open.get(incident_id)
        if case is None:
            return None
        return {"deadline": case.deadline, "acked_by": case.acked_by,
                "auto": self._auto}

    # -- clock ---------------------------------------------------------------- #

    def tick(self) -> int:
        """Reminders and deadline actions. Returns automatic actions taken."""
        from datetime import timedelta
        now = self._clock()
        pending = self._engine.pending_approvals()
        taken = 0
        for iid in list(self._open):
            case = self._open[iid]
            dec = pending.get(iid)
            if dec is None:                       # resolved elsewhere
                self._open.pop(iid, None)
                continue
            if now >= case.deadline:
                if self._auto and not case.acked_by:
                    taken += int(self._deadline_action(iid, case))
                else:
                    why = ("acknowledged by " + case.acked_by) if case.acked_by \
                        else "automatic action disabled"
                    self._audit(iid, "critical_deadline_passed", why)
                    self._notify_text(
                        dec, case, "انتهت المهلة",
                        f"انتهى الوقت ولم يُتخذ إجراء تلقائي ({why}). الحالة ما زالت تحتاج قرارًا.")
                    self._open.pop(iid, None)
                continue
            if now >= case.next_reminder:
                case.reminders += 1
                case.next_reminder = now + timedelta(seconds=self._reminder_s)
                self._send(dec, case, first=False)
        return taken

    # -- internals --------------------------------------------------------------- #

    def _deadline_action(self, iid: str, case: _Case) -> int:
        self._open.pop(iid, None)
        try:
            decision = self._engine.resolve(iid, True, by_deadline=True,
                                            actor="sentinel_timeout")
        except KeyError:
            return False
        if self._record_decision is not None:
            self._record_decision(decision, "deadline")
        if decision.outcome.value not in ("auto_act", "auto_throttle"):
            self._audit(iid, "critical_deadline_passed",
                        "Tier C cannot be acted on automatically")
            self._notify_text(
                decision, case, "انتهت المهلة دون تنفيذ تلقائي",
                "انتهت المهلة، لكن فئة الدليل C تمنع التنفيذ التلقائي. راجع الحالة يدويًا.")
            return False
        verdicts = []
        if self._executor is not None:
            from sentinel.decision.models import Recommendation
            actions = (decision.inputs or {}).get("fallback_actions") or []
            plans = [decision]
            for action in actions[1:]:
                plans.append(replace(decision, recommendation=Recommendation(
                    action=action, params={"target": "src", "ttl_minutes": 15},
                    because="preconfigured report-timeout protective plan")))
            for plan in plans:
                verdicts.append(self._executor.handle(
                    plan, dict(case.ctx, incident_id=iid), "deadline",
                    case_id="deadline"))
        executed_count = sum(v == "executed" for v in verdicts)
        self.auto_actions += executed_count
        executed = executed_count > 0
        event = ("critical_deadline_auto_action" if executed
                 else "critical_deadline_action_withheld")
        self._audit(iid, event, f"executor verdicts: {verdicts}")
        log.warning(event, incident_id=iid, verdicts=verdicts)
        title = ("تصرّف تلقائي بعد انتهاء المهلة" if executed
                 else "انتهت المهلة دون تنفيذ الإجراء")
        self._notify_text(
            decision, case, title,
            f"انتهت المهلة. نتيجة محاولة التنفيذ: {', '.join(str(v) for v in verdicts) or 'لا منفّذ'}.")
        return executed_count

    def _audit(self, incident_id: str, name: str, detail: str) -> None:
        self._store.record_action(
            case_id="escalation", action_type=name, target_ip=None,
            ttl_minutes=None, verdict=name, executed=False,
            detail=f"{incident_id}: {detail}")

    def _plan(self, decision, case: _Case) -> str:
        rec = decision.recommendation
        act = rec.action if rec else "لا شيء"
        if decision.tier == "C":
            return "فئة الدليل C تحتاج قرارًا بشريًا؛ لن يتصرف النظام تلقائيًا."
        if not self._auto:
            return "لن يتصرف النظام تلقائيًا؛ القرار بيدك."
        if case.acked_by:
            return f"استلمها {case.acked_by}: لن يتصرف النظام تلقائيًا."
        if decision.outcome.value == "report_wait":
            act = ", ".join((decision.inputs or {}).get("fallback_actions") or
                            ["throttle_src"]) + " (15 دقيقة)"
        return (f"إن لم يُتخذ قرار قبل {_fmt_clock(case.deadline)} "
                f"سينفّذ Sentinel بنفسه: {act} (مؤقتًا ومع إمكانية التراجع).")

    def _send(self, decision, case: _Case, first: bool) -> None:
        if self._hub is None:
            return
        ctx = case.ctx
        left = max(0, int((case.deadline - self._clock()).total_seconds() // 60))
        critical = decision.outcome.value == "human_approval"
        title = (("حالة حرجة تحتاج قرارًا الآن" if critical
                  else "حالة تحتاج قرارًا الآن") if first
                 else f"تذكير: حالة {'حرجة' if critical else 'معلّقة'}، باقي {left} دقيقة")
        body = (
            f"{ctx.get('src_ip', '?')} ← {ctx.get('dst_ip', '?')} · "
            f"الدرجة {float(decision.score):.0%} · الفئة {decision.tier}\n"
            f"المطلوب: اعتماد أو رفض (/approve أو /deny ثم رقم الحالة)، أو /ack للاستلام.\n"
            f"الموعد النهائي: {_fmt_clock(case.deadline)} (باقي {left} دقيقة).\n"
            f"{self._plan(decision, case)}\n{decision.would}")
        self._hub.notify_urgent(Notification(
            title=title, body=body,
            severity="critical" if decision.outcome.value == "human_approval" else "high",
            incident_id=decision.incident_id, outcome=decision.outcome.value,
            approval_id=decision.incident_id))

    def _notify_text(self, decision, case: _Case, title: str, body: str) -> None:
        if self._hub is None:
            return
        self._hub.notify_urgent(Notification(
            title=title,
            body=f"{case.ctx.get('src_ip', '?')} ← {case.ctx.get('dst_ip', '?')}\n{body}",
            severity="critical", incident_id=decision.incident_id,
            outcome=decision.outcome.value, approval_id=None))
