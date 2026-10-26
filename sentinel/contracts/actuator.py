"""ABC #2 — Actuator adapter contract (§4).

All enforcement integrations implement this interface: nftables local rules,
firewall REST APIs, SOAR/webhook dispatchers. Core never knows vendor details
(P2), and NO code path may reach an actuator without passing the full §3.1
validator chain (G6 — enforced from M4 onward).
"""
from __future__ import annotations

import abc
from typing import ClassVar

from sentinel.models import Action, ActionResult


class Actuator(abc.ABC):
    """Typed interface every enforcement adapter must implement.

    Contract (§4 Adapter contract ABC #2):

    * ``execute(action)`` performs ONE validated action and returns an
      :class:`sentinel.models.ActionResult`. On success it SHOULD return a
      ``rollback_token`` enabling one-command reversal (G3: all auto-blocks
      temporary, TTL <= 60 min, auto-expire scheduler + `sentinel ctl rollback`).

    * ``rollback(token)`` undoes a previously executed action identified by
      its token. Must be idempotent: rolling back an already-rolled-back or
      expired action succeeds quietly rather than raising.

    * Implementations must be side-effect-safe under dry-run: when the core
      runs with dry_run=True (the DEFAULT per G2/P5), execute() is invoked in
      simulation mode by the caller and MUST NOT mutate any real system.
    """

    #: stable actuator identifier for audit provenance (e.g. "nftables_local")
    name: ClassVar[str] = "actuator"

    @abc.abstractmethod
    def execute(self, action: Action) -> ActionResult:
        """Execute one protective action; return ActionResult with rollback handle."""
        raise NotImplementedError

    @abc.abstractmethod
    def rollback(self, token: str) -> ActionResult:
        """Undo a prior execution by rollback token (idempotent)."""
        raise NotImplementedError
