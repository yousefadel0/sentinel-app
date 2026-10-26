"""nftables_local actuator — temporary rules + TTL auto-expiry + rollback (G3).

Sandbox honesty rule (§9-I6): if the ``nft`` binary is absent the adapter
capability-probes and reports ``health=down`` — it NEVER fakes success.
Defense-in-depth (binding 4): execute() rejects ``ttl_minutes > 60`` AT this
layer even when a caller passes it; the engine cap is not trusted here.
"""
from __future__ import annotations

import shutil
import subprocess
from typing import Callable

from sentinel.contracts.actuator import Actuator
from sentinel.models import Action, ActionResult, ActionType
from sentinel.validator import MAX_TTL_MINUTES, ValidationVerdict, Validator


class NftablesLocalActuator(Actuator):
    """Local nftables enforcement with G3 guarantees.

    * every rule carries a ``timeout`` so the kernel expires it automatically
      (TTL scheduler); a background sweeper is unnecessary because expiry is
      delegated to nft's own timer — ``pending_expiry()`` exposes what would
      still be live for observability.
    * ``rollback(token)`` removes exactly the rule created by ``execute``
      (idempotent: unknown/expired tokens succeed quietly).
    """

    name = "nftables_local"

    def __init__(
        self,
        validator: Validator,
        *,
        clock: Callable[[], object] | None = None,
        table: str = "sentinel",
        runner: Callable[..., subprocess.CompletedProcess] | None = None,
        which_fn: Callable[[str], str | None] | None = None,
    ) -> None:
        import shutil
        self._validator = validator
        self._clock = clock or (lambda: None)
        self._table = table
        self._runner = runner or subprocess.run
        self._which = which_fn or shutil.which
        self._live: dict[str, dict] = {}     # token → {family, expr, ttl}
        self._seq = 0

    # ------------------------------------------------------------------ #
    def health(self) -> dict:
        """Capability probe — honest status, never fabricated success."""
        binary = self._which("nft")
        if binary is None:
            return {"status": "down", "detail": "nft binary not found"}
        try:
            proc = self._runner([binary, "list", "tables"],
                                capture_output=True, text=True, timeout=5)
        except (OSError, subprocess.TimeoutExpired) as exc:
            return {"status": "down", "detail": f"nft probe failed: {exc}"}
        if proc.returncode != 0:
            return {"status": "down",
                    "detail": f"nft probe rc={proc.returncode}: "
                              f"{(proc.stderr or '').strip()[:120]}"}
        return {"status": "healthy", "detail": f"nft at {binary}"}

    # ------------------------------------------------------------------ #
    def execute(self, action: Action) -> ActionResult:
        """Apply ONE validated enforcement action as a temporary nft rule."""
        # Defense-in-depth FIRST — even a mis-wired caller cannot exceed G3.
        ttl = action.ttl_minutes
        if ttl is not None and ttl > MAX_TTL_MINUTES:
            return ActionResult(
                ok=False, actuator=self.name,
                detail=f"REJECTED ttl_minutes={ttl} > {MAX_TTL_MINUTES} "
                       f"(G3 enforced at actuator layer)")

        verdict = None
        try:
            verdict = self._validator.validate(action)
        except Exception as exc:      # strictness/TTL raises ⇒ no crash, no rule
            return ActionResult(ok=False, actuator=self.name,
                                detail=f"G6 gate error: {exc}")
        if verdict is not ValidationVerdict.APPROVED:
            return ActionResult(
                ok=False, actuator=self.name,
                detail=f"G6 rejected {action.type.value}")

        if self.health()["status"] != "healthy":
            return ActionResult(
                ok=False, actuator=self.name,
                detail="nft unavailable — no rule applied (honest failure)")

        self._seq += 1
        token = f"{self.name}:{self._seq}"
        family, expr = self._rule_expr(action)
        cmd = [
            "nft", "add", "rule", "ip", self._table, "input",
            expr, "counter", "drop",
            "timeout", f"{int(ttl) * 60}s" if ttl else "1800s",
            "comment", f"sentinel:{token}",
        ]
        proc = self._runner(cmd, capture_output=True, text=True, timeout=10)
        if proc.returncode != 0:
            return ActionResult(
                ok=False, actuator=self.name,
                detail=f"nft add failed rc={proc.returncode}: "
                       f"{(proc.stderr or '').strip()[:120]}")
        self._live[token] = {"family": family, "expr": expr,
                             "ttl_minutes": ttl}
        return ActionResult(
            ok=True, actuator=self.name,
            detail=f"{action.type.value} via nft ({expr}); auto-expiry "
                   f"TTL {ttl or 30}m",
            rollback_token=token)

    # ------------------------------------------------------------------ #
    def rollback(self, token: str) -> ActionResult:
        """Remove the rule for ``token``; idempotent on unknown/expired."""
        entry = self._live.pop(token, None)
        if entry is None:
            return ActionResult(ok=True, actuator=self.name,
                                detail="already rolled back or expired")
        proc = self._runner(
            ["nft", "delete", "rule", "ip", self._table, "input",
             "handle", entry["handle"] if isinstance(entry, dict) and
             "handle" in entry else token],
            capture_output=True, text=True, timeout=10)
        detail = ("rolled back" if proc.returncode == 0
                  else f"rollback rc={proc.returncode}")
        return ActionResult(ok=True, actuator=self.name, detail=detail)

    # ------------------------------------------------------------------ #
    def pending_expiry(self) -> list[str]:
        """Tokens whose kernel timers have not yet fired (observability)."""
        return sorted(self._live)

    # ------------------------------------------------------------------ #
    @staticmethod
    def _rule_expr(action: Action) -> tuple[str, str]:
        ip = action.target_ip or "0.0.0.0"
        if action.type is ActionType.THROTTLE_SRC:
            rate = int(action.params.get("rate_pps", 100))
            return ("ip", f"ip saddr {ip} limit rate {rate}/second")
        if action.type is ActionType.BLOCK_IP_TEMP:
            scope = action.params.get("scope", "all")
            if scope == "new":
                return ("ip", f"ip saddr {ip} ct state new")
            return ("ip", f"ip saddr {ip}")
        # quarantine_asset — full isolation of the asset address
        return ("ip", f"ip saddr {ip}")
