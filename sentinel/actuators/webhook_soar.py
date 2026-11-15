"""webhook_soar actuator — schema-validated POST with bounded retry/backoff.

Offline ⇒ degrades to a ``log_only`` audit event and returns an honest
non-crashing ActionResult (binding 3). Payload schema is validated BEFORE any
network I/O; retries are bounded by config, never infinite.
"""
from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any, Callable

from sentinel.models import Action, ActionResult, ActionType
from sentinel.validator import ValidationVerdict, Validator

#: Bounded retry policy (never unbounded).
MAX_ATTEMPTS = 3
BACKOFF_SECONDS = (0.5, 1.0)   # between attempt 1→2 and 2→3


class _PayloadError(ValueError):
    """Raised when a payload fails schema validation before POSTing."""


def _validate_payload(payload: dict[str, Any]) -> None:
    """Strict §5-style schema for SOAR dispatch — fail closed pre-network."""
    required = {"incident_id", "action", "target_ip", "ttl_minutes",
                "rationale", "audit_events"}
    missing = required - set(payload)
    if missing:
        raise _PayloadError(f"payload missing keys: {sorted(missing)}")
    if not isinstance(payload["action"], str) or not payload["action"]:
        raise _PayloadError("payload.action must be a non-empty string")
    aggressive = payload["action"] in ("throttle_src", "block_ip_temp",
                                       "quarantine_asset")
    if aggressive and (
            not isinstance(payload["target_ip"], str)
            or not payload["target_ip"].strip()):
        raise _PayloadError(
            f"payload.target_ip required for {payload['action']}: "
            f"{payload['target_ip']!r}")
    if payload["ttl_minutes"] is not None and (
            not isinstance(payload["ttl_minutes"], int)
            or payload["ttl_minutes"] < 1 or payload["ttl_minutes"] > 60):
        raise _PayloadError(
            f"payload.ttl_minutes invalid: {payload['ttl_minutes']!r}")
    if not isinstance(payload["audit_events"], list):
        raise _PayloadError("payload.audit_events must be a list")


class WebhookSoarActuator:
    """POST verdict/action payloads to the operator's SOAR endpoint."""

    name = "webhook_soar"
    supports_rollback = False

    def __init__(
        self,
        validator: Validator,
        url: str,
        *,
        token_env: str = "SENTINEL_SOAR_TOKEN",
        urlopen: Callable[..., Any] | None = None,
        sleeper: Callable[[float], None] | None = None,
        timeout_s: float = 5.0,
    ) -> None:
        self._validator = validator
        self._url = url
        self._token_env = token_env
        self._urlopen = urlopen or urllib.request.urlopen
        self._sleep = sleeper or (lambda s: None)
        self._timeout_s = timeout_s

    # ------------------------------------------------------------------ #
    def health(self) -> dict:
        return {"status": "healthy", "detail": self._url}

    # ------------------------------------------------------------------ #
    def execute(self, action: Action, *, incident_id: str = "",
                audit_events: list[dict] | None = None) -> ActionResult:
        """Validate → schema-check → POST with bounded retries.

        Network failure after the retry budget ⇒ ``ok=False`` with a
        ``log_only`` degradation note; NEVER raises.
        """
        verdict = None
        try:
            verdict = self._validator.validate(action)
        except Exception as exc:      # strictness/TTL raises ⇒ honest no-crash
            return ActionResult(ok=False, actuator=self.name,
                                detail=f"G6 gate error: {exc}")
        if verdict is not ValidationVerdict.APPROVED:
            return ActionResult(
                ok=False, actuator=self.name,
                detail=f"G6 rejected {action.type.value}")

        payload = {
            "incident_id": incident_id,
            "action": (action.type.value
                       if isinstance(action.type, ActionType)
                       else str(action.type)),
            "target_ip": action.target_ip,
            "ttl_minutes": action.ttl_minutes,
            "rationale": action.rationale,
            "audit_events": audit_events or [],
        }
        try:
            _validate_payload(payload)
        except _PayloadError as exc:
            return ActionResult(ok=False, actuator=self.name,
                                detail=f"payload schema rejected: {exc}")

        return self._post(payload)

    # ------------------------------------------------------------------ #
    def execute_upstream(self, *, action_name: str, target_ip: str,
                         ttl_minutes: int, rationale: str,
                         incident_id: str = "",
                         audit_events: list[dict] | None = None) -> ActionResult:
        """Ask the operator's SOAR/firewall to mitigate upstream (DDoS
        playbook: Sentinel is SPAN-only, so it asks, it never blocks itself).
        Same schema check, bounded retries and honest degradation as execute()."""
        payload = {"incident_id": incident_id, "action": action_name,
                   "target_ip": target_ip, "ttl_minutes": ttl_minutes,
                   "rationale": rationale, "audit_events": audit_events or []}
        try:
            _validate_payload(payload)
        except _PayloadError as exc:
            return ActionResult(ok=False, actuator=self.name,
                                detail=f"payload schema rejected: {exc}")
        return self._post(payload)

    def _post(self, payload: dict) -> ActionResult:
        import os
        body = json.dumps(payload).encode()
        last_err = ""
        for attempt in range(MAX_ATTEMPTS):
            headers = {"Content-Type": "application/json"}
            token = os.environ.get(self._token_env)
            if token:
                headers["Authorization"] = f"Bearer {token}"
            req = urllib.request.Request(self._url, data=body,
                                         headers=headers, method="POST")
            try:
                with self._urlopen(req, timeout=self._timeout_s) as resp:
                    status = getattr(resp, "status", 200)
                if 200 <= status < 300:
                    return ActionResult(
                        ok=True, actuator=self.name,
                        detail=f"SOAR dispatch accepted (HTTP {status})",
                        rollback_token=None)
                last_err = f"HTTP {status}"
            except (urllib.error.URLError, OSError, ValueError) as exc:
                last_err = str(exc)[:120]
            if attempt < MAX_ATTEMPTS - 1:
                self._sleep(BACKOFF_SECONDS[min(attempt,
                                               len(BACKOFF_SECONDS) - 1)])
        # Offline / exhausted budget => honest degrade to log_only, no crash.
        return ActionResult(
            ok=False, actuator=self.name,
            detail=f"log_only degradation after {MAX_ATTEMPTS} attempts "
                   f"(offline: {last_err})")

    # ------------------------------------------------------------------ #
    def rollback(self, token: str) -> ActionResult:
        """Webhooks are not reversible — idempotent quiet success."""
        return ActionResult(ok=True, actuator=self.name,
                            detail="webhook actions carry no rollback handle")
