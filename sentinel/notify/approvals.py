"""Chat approvals over Telegram long-polling (outbound-only: no inbound port).

Two ways to answer, both from the ONE configured chat:

* tap a button under an alert (inline keyboard -> ``callback_query``);
* type ``/approve <id>``, ``/deny <id>`` or ``/ack <id>``.

When ``allowed_user_ids`` is configured only those Telegram accounts may
decide — being in the group is not enough. Every request carries the
Telegram identity of the person who pressed, so the audit trail names them.

This module never touches the engine or the store: requests are handed to
the daemon loop, which applies them through the same ``Engine.resolve``
seam as the Ops UI and CLI (same validator chain, window and audit trail).
"""
from __future__ import annotations

import json
import os
import queue
import re
import threading
import urllib.parse
import urllib.request
from typing import Callable, Iterable

from sentinel.logging_setup import get_logger

log = get_logger("sentinel.notify.approvals")

Fetch = Callable[[str, float], dict]
_CMD = re.compile(r"^/(approve|deny|ack)(?:@\w+)?\s+([A-Za-z0-9_.:-]{1,128})\s*$")
_CB = re.compile(r"^(approve|deny|ack):([A-Za-z0-9_.:-]{1,100})$")
_REPLY = {"approve": "✅ تم تسجيل الاعتماد", "deny": "⛔ تم تسجيل الرفض",
          "ack": "👀 تم تسجيل الاستلام"}


def _urllib_fetch(url: str, timeout: float) -> dict:
    with urllib.request.urlopen(url, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _who(user: dict) -> str:
    name = user.get("username") or user.get("first_name") or "?"
    return f"telegram:{name}#{user.get('id', '?')}"


class TelegramApprovals:
    API = "https://api.telegram.org"

    def __init__(self, token_env: str, chat_id: str, *,
                 fetch: Fetch | None = None, interval_s: float = 3.0,
                 timeout_s: float = 5.0,
                 allowed_user_ids: Iterable[str] | None = None) -> None:
        self._env, self._chat = token_env, str(chat_id)
        self._fetch = fetch or _urllib_fetch
        self._interval, self._timeout = interval_s, timeout_s
        self._allowed = {str(u) for u in (allowed_user_ids or [])}
        self._offset = 0
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()

    def _may_decide(self, user: dict) -> bool:
        return not self._allowed or str(user.get("id")) in self._allowed

    def _answer(self, token: str, cq_id: str, text: str) -> None:
        q = urllib.parse.urlencode({"callback_query_id": cq_id, "text": text})
        try:
            self._fetch(f"{self.API}/bot{token}/answerCallbackQuery?{q}", self._timeout)
        except Exception as exc:                  # cosmetic only
            log.warning("telegram_answer_failed", error=type(exc).__name__)

    def poll_once(self) -> list[tuple]:
        """[(approval_id, approved|None, actor), ...] from authorised people."""
        token = os.environ.get(self._env)
        if not token:
            return []
        url = (f"{self.API}/bot{token}/getUpdates?offset={self._offset}&timeout=0"
               "&allowed_updates=%5B%22message%22%2C%22callback_query%22%5D")
        data = self._fetch(url, self._timeout)
        out: list[tuple] = []
        for upd in data.get("result", []):
            self._offset = max(self._offset, int(upd.get("update_id", 0)) + 1)
            cq = upd.get("callback_query")
            if cq:
                chat = ((cq.get("message") or {}).get("chat") or {}).get("id")
                user = cq.get("from") or {}
                m = _CB.match(str(cq.get("data", "")))
                if str(chat) != self._chat or not m:
                    continue
                if not self._may_decide(user):
                    self._answer(token, cq.get("id", ""), "غير مصرّح لك بهذا القرار")
                    log.warning("telegram_unauthorised", user=_who(user))
                    continue
                verb, aid = m.group(1), m.group(2)
                out.append((aid, None if verb == "ack" else verb == "approve", _who(user)))
                self._answer(token, cq.get("id", ""), _REPLY[verb])
                continue
            msg = upd.get("message") or {}
            if str((msg.get("chat") or {}).get("id")) != self._chat:
                continue                         # other chats have no authority
            m = _CMD.match(str(msg.get("text", "")).strip())
            user = msg.get("from") or {}
            if m and self._may_decide(user):
                # approve -> True, deny -> False, ack -> None (acknowledge only)
                out.append((m.group(2),
                            None if m.group(1) == "ack" else m.group(1) == "approve",
                            _who(user)))
        return out

    def start(self, sink: "queue.Queue[tuple]") -> None:
        def loop() -> None:
            while not self._stop.is_set():
                try:
                    for req in self.poll_once():
                        sink.put(req)
                except Exception as exc:          # P4: network blips are normal
                    log.warning("telegram_poll_failed",
                                error=type(exc).__name__)
                self._stop.wait(self._interval)

        self._thread = threading.Thread(target=loop, daemon=True,
                                        name="telegram-approvals")
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
