"""Notification transports. Secrets (webhook URLs, bot tokens) are NEVER in
config files — each sender reads the value from an environment variable at
send time, exactly like the LLM endpoint (§8)."""
from __future__ import annotations

import json
import os
import urllib.request
from typing import Callable

Transport = Callable[[str, dict, float], int]   # (url, json_body, timeout)->status


def _urllib_transport(url: str, body: dict, timeout: float) -> int:
    req = urllib.request.Request(
        url, data=json.dumps(body).encode("utf-8"),
        headers={"Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return int(resp.status)


_ICON = {"critical": "🔴", "high": "🟠", "medium": "🟡", "info": "🔵"}


def _text(n) -> str:
    lines = [f"{_ICON.get(n.severity, '⚪')} Sentinel · {n.title}", n.body]
    if n.approval_id:
        lines.append(f"رقم الحالة: {n.approval_id}")
    return "\n".join(lines)


def _buttons(n) -> dict | None:
    """Inline keyboard: approve / deny / acknowledge, straight from the phone."""
    if not n.approval_id:
        return None
    aid = n.approval_id[:100]
    return {"inline_keyboard": [[
        {"text": "✅ اعتماد", "callback_data": f"approve:{aid}"},
        {"text": "⛔ رفض", "callback_data": f"deny:{aid}"},
        {"text": "👀 استلمت", "callback_data": f"ack:{aid}"}]]}


class WebhookSender:
    """Slack / Microsoft Teams / generic JSON webhook."""

    def __init__(self, url_env: str, fmt: str = "generic", *,
                 transport: Transport | None = None, timeout_s: float = 5.0):
        if fmt not in ("slack", "teams", "generic"):
            raise ValueError(f"unknown webhook format {fmt!r}")
        self.name = f"webhook:{fmt}"
        self._env, self._fmt = url_env, fmt
        self._transport = transport or _urllib_transport
        self._timeout = timeout_s

    def send(self, n) -> bool:
        url = os.environ.get(self._env)
        if not url:
            return False
        if self._fmt in ("slack", "teams"):
            body = {"text": _text(n)}
        else:
            body = {"title": n.title, "body": n.body, "severity": n.severity,
                    "incident_id": n.incident_id, "outcome": n.outcome,
                    "approval_id": n.approval_id}
        return 200 <= self._transport(url, body, self._timeout) < 300


class TelegramSender:
    """Telegram Bot API sendMessage. Token comes from ``token_env``."""

    API = "https://api.telegram.org"

    def __init__(self, token_env: str, chat_id: str, *,
                 transport: Transport | None = None, timeout_s: float = 5.0):
        self.name = "telegram"
        self._env, self._chat = token_env, str(chat_id)
        self._transport = transport or _urllib_transport
        self._timeout = timeout_s

    def send(self, n) -> bool:
        token = os.environ.get(self._env)
        if not token:
            return False
        url = f"{self.API}/bot{token}/sendMessage"
        body = {"chat_id": self._chat, "text": _text(n)}
        markup = _buttons(n)
        if markup:
            body["reply_markup"] = markup
        status = self._transport(url, body, self._timeout)
        return 200 <= status < 300
