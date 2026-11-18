"""Daily Telegram/webhook summary: once per day, after the configured hour."""
from datetime import datetime, timezone

from sentinel.auditstore.store import Store
from sentinel.daemon import Daemon
from sentinel.decision import AutonomyController, DecisionEngine, RateLimiter
from tests.fixtures.decision.helpers import config_view


class Hub:
    def __init__(self):
        self.sent = []

    def notify_urgent(self, n):
        self.sent.append(n)
        return True

    def notify(self, *a):
        return False

    def close(self):
        pass


def test_summary_sent_once_per_day_after_hour(tmp_path):
    now = [datetime(2026, 11, 18, 6, 0, tzinfo=timezone.utc)]
    store = Store(tmp_path / "audit.sqlite")
    store.record_decision(case_id="live", incident_id="inc-1", outcome="human_approval",
                          score=0.7, base_score=0.7, tier="A", cap_applied=None,
                          would="x", recommendation={}, audit_events=[])
    store.record_incident_context(incident_id="inc-1", src_ip="203.0.113.9",
                                  dst_ip="10.0.0.4", attack_type="Brute force",
                                  signals=[], alert_count=4, first_ts="", last_ts="",
                                  evidence=[], mitre=[])
    eng = DecisionEngine(config_view=config_view(), clock=lambda: now[0],
                         rate_limiter=RateLimiter(5, 20),
                         controller=AutonomyController(level=0))
    hub = Hub()
    d = Daemon(sources=[], engine=eng, store=store, hub=hub, clock=lambda: now[0])
    d.summary_hour_utc = 7
    assert d._maybe_daily_summary() is False          # before 07:00
    now[0] = datetime(2026, 11, 18, 7, 5, tzinfo=timezone.utc)
    assert d._maybe_daily_summary() is True
    assert "203.0.113.9" in hub.sent[0].body
    assert d._maybe_daily_summary() is False          # once per day
    now[0] = datetime(2026, 11, 19, 7, 1, tzinfo=timezone.utc)
    assert d._maybe_daily_summary() is True
    store.close()
