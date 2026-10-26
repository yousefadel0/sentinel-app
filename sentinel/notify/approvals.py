"""Chat approvals over Telegram long-polling (outbound-only: no inbound port).

``/approve <id>`` and ``/deny <id>`` from the ONE configured chat become
(approval_id, approved) requests. This module never touches the engine or
the store: requests are handed to the daemon loop, which applies them
through the same ``Engine.resolve`` seam as the Ops UI and CLI, so the
validator chain, the 15-minute window and the audit trail are identical.
Messages from any other chat are ignored.
"""
from __future__ import annotations

import json
import os
import queue
import re
import threading
import urllib.request
from typing import Callable

from sentinel.logging_setup import get_logger

log = get_logger("sentinel.notify.approvals")

Fetch = Callable[[str, float], dict]
_CMD = re.compile(r"^/(approve|deny)(?:@\w+)?\s+([A-Za-z0-9_.:-]{1,128})\s*$")


def _urllib_fetch(url: str, timeout: float) -> dict:
    with urllib.request.urlopen(url, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


class TelegramApprovals:
    API = "https://api.telegram.org"

    def __init__(self, token_env: str, chat_id: str, *,
                 fetch: Fetch | None = None, interval_s: float = 3.0,
                 timeout_s: float = 5.0) -> None:
        self._env, self._chat = token_env, str(chat_id)
        self._fetch = fetch or _urllib_fetch
        self._interval, self._timeout = interval_s, timeout_s
        self._offset = 0
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()

    def poll_once(self) -> list[tuple[str, bool]]:
        token = os.environ.get(self._env)
        if not token:
            return []
        url = (f"{self.API}/bot{token}/getUpdates?offset={self._offset}"
               f"&timeout=0&allowed_updates=%5B%22message%22%5D")
        data = self._fetch(url, self._timeout)
        out: list[tuple[str, bool]] = []
        for upd in data.get("result", []):
            self._offset = max(self._offset, int(upd.get("update_id", 0)) + 1)
            msg = upd.get("message") or {}
            if str((msg.get("chat") or {}).get("id")) != self._chat:
                continue                         # other chats have no authority
            m = _CMD.match(str(msg.get("text", "")).strip())
            if m:
                out.append((m.group(2), m.group(1) == "approve"))
        return out

    def start(self, sink: "queue.Queue[tuple[str, bool]]") -> None:
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
