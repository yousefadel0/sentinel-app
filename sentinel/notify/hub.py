"""NotifierHub — fan a decision out to every configured channel.

Safety properties (P4/P5):
* never raises and never blocks the capture loop (one worker thread);
* only outcomes that need a human or describe action are sent — log_only
  stays in the audit store;
* a story is re-sent only when its outcome changes or after ``dedupe_s``;
* a global per-minute cap stops a flood from becoming a notification storm
  (suppressed sends are counted, never silently lost: ``hub.suppressed``);
* messages carry IPs, outcome, score and the engine's own explanation —
  never raw payloads.
"""
from __future__ import annotations

import time
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass

from sentinel.logging_setup import get_logger

log = get_logger("sentinel.notify")

NOTIFY_OUTCOMES = frozenset({"human_approval", "escalate_human", "auto_act",
                             "auto_throttle", "notify_only", "report_wait"})
_SEVERITY = {"auto_act": "critical", "auto_throttle": "high",
             "human_approval": "high", "escalate_human": "high",
             "report_wait": "medium", "notify_only": "info"}
_TITLE_AR = {"human_approval": "هجوم يحتاج موافقتك",
             "escalate_human": "تصعيد: يحتاج قرارًا بشريًا",
             "auto_act": "تم التصرف تلقائيًا", "auto_throttle": "تم تقييد المصدر تلقائيًا",
             "report_wait": "تقرير ينتظر المراجعة", "notify_only": "للعلم"}
_ACTION_AR = {"block_ip_temp": "حظر مؤقت للمصدر", "throttle_src": "تقييد سرعة المصدر",
              "quarantine_host": "عزل الجهاز", "notify_only": "إشعار فقط",
              "rate_limit_upstream": "تحديد المعدل عند المزوّد"}
#: Outcomes a human can answer from the chat (buttons are attached).
DECIDABLE = frozenset({"human_approval", "report_wait"})


@dataclass(frozen=True)
class Notification:
    title: str
    body: str
    severity: str
    incident_id: str
    outcome: str
    approval_id: str | None = None


def build_notification(decision, incident) -> Notification:
    outcome = decision.outcome.value
    rec = decision.recommendation
    conf = (getattr(decision, "inputs", None) or {}).get("confidence")
    from sentinel.threatintel.attack import map_incident
    signals = tuple(getattr(incident, "signals", ()) or
                    {s for a in getattr(incident, "alerts", ()) for s in a.signals})
    mapping = map_incident(signals)
    kind = mapping.attack_type if mapping else (", ".join(signals) or "suspicious activity")
    lines = [f"النوع: {kind}",
             f"المصدر ← الهدف: {incident.src_ip} → {incident.dst_ip}",
             f"الخطورة {float(decision.score):.0%}"
             + (f" · الثقة {float(conf):.0%}" if conf is not None else "")
             + f" · {len(incident.alerts)} تنبيه"]
    if rec:
        lines.append(f"الإجراء المقترح: {_ACTION_AR.get(rec.action, rec.action)}")
    lines.append(f"السبب: {decision.would}")
    deadline = getattr(decision, "approval_deadline", None)
    if deadline:
        lines.append(f"المهلة حتى: {deadline.strftime('%H:%M')} UTC")
    return Notification(
        title=f"{_TITLE_AR.get(outcome, outcome)} · {incident.src_ip} → {incident.dst_ip}",
        body="\n".join(lines),
        severity=_SEVERITY.get(outcome, "info"),
        incident_id=decision.incident_id,
        outcome=outcome,
        approval_id=(decision.incident_id if outcome in DECIDABLE else None),
    )


class NotifierHub:
    def __init__(self, senders, *, dedupe_s: float = 600.0,
                 max_per_min: int = 20, clock=time.monotonic,
                 synchronous: bool = False) -> None:
        self._senders = list(senders)
        self._dedupe = dedupe_s
        self._max = max_per_min
        self._clock = clock
        self._sync = synchronous
        self._pool = ThreadPoolExecutor(max_workers=1,
                                        thread_name_prefix="notify")
        self._recent: dict[tuple[str, str, str], float] = {}
        self._sent: deque[float] = deque()
        self.suppressed = 0
        self.failures = 0
        self.delivered = 0

    def notify(self, decision, incident) -> bool:
        """Queue a notification; returns True when it was accepted."""
        outcome = decision.outcome.value
        if not self._senders or outcome not in NOTIFY_OUTCOMES:
            return False
        now = self._clock()
        key = (incident.src_ip, incident.dst_ip, outcome)
        last = self._recent.get(key)
        if last is not None and now - last < self._dedupe:
            return False
        while self._sent and now - self._sent[0] > 60:
            self._sent.popleft()
        if len(self._sent) >= self._max:
            self.suppressed += 1
            return False
        self._recent[key] = now
        self._sent.append(now)
        n = build_notification(decision, incident)
        if self._sync:
            self._deliver(n)
        else:
            self._pool.submit(self._deliver, n)
        return True

    def notify_urgent(self, n: Notification) -> bool:
        """Critical escalation message: bypasses dedupe and the rate cap, and
        is delivered synchronously so the caller knows it was attempted."""
        if not self._senders:
            return False
        self._deliver(n)
        return True

    def _deliver(self, n: Notification) -> None:
        for s in self._senders:
            try:
                if s.send(n):
                    self.delivered += 1
                else:
                    self.failures += 1
            except Exception as exc:          # P4: a dead channel is not fatal
                self.failures += 1
                log.warning("notify_failed", sender=s.name,
                            error=type(exc).__name__)

    def close(self) -> None:
        self._pool.shutdown(wait=True, cancel_futures=False)
