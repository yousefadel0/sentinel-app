"""Telegram: Arabic alert with approve/deny/ack buttons; only allowed people decide."""
from sentinel.decision.chain import Facts
from sentinel.notify import TelegramSender, build_notification
from sentinel.notify.approvals import TelegramApprovals
from tests.fixtures.decision.helpers import FakeClock, IncidentStub, alert, engine


class Inc(IncidentStub):
    src_ip = "198.51.100.7"
    dst_ip = "10.0.0.4"


def _n():
    eng, _ = engine(clock=FakeClock())
    inc = Inc([alert("auth_fail_burst", 0.93, crit="critical")])
    d = eng.evaluate(inc, Facts(liveness="alive"))
    return build_notification(d, inc)


def test_alert_message_is_arabic_and_has_decision_buttons(monkeypatch):
    n = _n()
    calls = []
    monkeypatch.setenv("TG", "1:a")
    TelegramSender("TG", "42", transport=lambda u, b, t: calls.append(b) or 200).send(n)
    body = calls[0]
    assert "198.51.100.7" in body["text"] and "المصدر" in body["text"]
    keys = [k["callback_data"] for k in body["reply_markup"]["inline_keyboard"][0]]
    assert keys == [f"approve:{n.approval_id}", f"deny:{n.approval_id}",
                    f"ack:{n.approval_id}"]


def _cb(update_id, chat, user, data):
    return {"update_id": update_id, "callback_query": {
        "id": f"cq{update_id}", "data": data, "from": {"id": user, "username": f"u{user}"},
        "message": {"chat": {"id": chat}}}}


def test_buttons_respect_chat_and_allowed_users(monkeypatch):
    monkeypatch.setenv("TG", "1:a")
    answered = []
    api = {"result": [_cb(1, 42, 7, "approve:inc-1"),     # allowed manager
                      _cb(2, 42, 8, "approve:inc-2"),     # in group, not allowed
                      _cb(3, 99, 7, "deny:inc-3"),        # other chat
                      _cb(4, 42, 7, "ack:inc-4"),
                      _cb(5, 42, 7, "approve:inc;rm")]}   # malformed

    def fetch(url, timeout):
        if "answerCallbackQuery" in url:
            answered.append(url)
            return {"ok": True}
        return api

    ap = TelegramApprovals("TG", "42", fetch=fetch, allowed_user_ids=["7"])
    got = ap.poll_once()
    assert got == [("inc-1", True, "telegram:u7#7"), ("inc-4", None, "telegram:u7#7")]
    assert len(answered) == 3                     # two decisions + one refusal
