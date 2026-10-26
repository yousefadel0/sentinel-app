"""nftables_local actuator — temporary enforcement with kernel-side expiry.

Design (validated against real nftables 1.1.x, see tests/test_nft_real.py):
three sets with ``flags timeout`` — ``blocked``, ``throttled``, ``quarantined``
— referenced by static rules in ``input`` AND ``forward`` chains. Enforcing an
action is ``add element <ip> timeout <N>m``; the kernel removes the element
when the timer fires (G3: TTL <= 60 min, no sweeper needed) and rollback is
``delete element``. State therefore lives in the kernel, so
``sentinel ctl rollback`` works from any process.

An earlier version added per-rule ``timeout``, which nft rejects with a
syntax error; its tests passed only because they used a scripted runner.

Sandbox honesty rule (§9-I6): if the ``nft`` binary is absent or unusable the
adapter reports ``health=down`` and fails honestly — it never fakes success.
Defense-in-depth: execute() rejects ``ttl_minutes > 60`` and never targets
unspecified/loopback/multicast/link-local addresses, independent of the engine.

Scope note: ``input`` protects this host and ``forward`` protects traffic the
host routes. A SPAN-only sensor routes nothing, so on such a box this actuator
is a host firewall; use ``webhook_soar`` (upstream) for the wider network.
"""
from __future__ import annotations

import ipaddress
import shutil
import subprocess
from typing import Callable

from sentinel.contracts.actuator import Actuator
from sentinel.models import Action, ActionResult, ActionType
from sentinel.validator import MAX_TTL_MINUTES, ValidationVerdict, Validator

_SETS = {
    ActionType.BLOCK_IP_TEMP: "blocked",
    ActionType.THROTTLE_SRC: "throttled",
    ActionType.QUARANTINE_ASSET: "quarantined",
}
DEFAULT_TTL_MINUTES = 30


class NftablesLocalActuator(Actuator):
    name = "nftables_local"

    def __init__(
        self,
        validator: Validator,
        *,
        clock: Callable[[], object] | None = None,
        table: str = "sentinel",
        runner: Callable[..., subprocess.CompletedProcess] | None = None,
        which_fn: Callable[[str], str | None] | None = None,
        throttle_pps: int = 100,
    ) -> None:
        self._validator = validator
        self._clock = clock or (lambda: None)
        self._table = table
        self._runner = runner or subprocess.run
        self._which = which_fn or shutil.which
        self._pps = int(throttle_pps)
        self._live: dict[str, dict] = {}
        self._ready = False

    # -- plumbing ------------------------------------------------------- #

    def _nft(self, *args: str):
        binary = self._which("nft") or "nft"
        try:
            return self._runner([binary, *args], capture_output=True,
                                text=True, timeout=10)
        except (OSError, subprocess.TimeoutExpired) as exc:
            return subprocess.CompletedProcess(
                [binary, *args], 127, "", f"nft unavailable: {exc}")

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

    def ensure_ruleset(self) -> str | None:
        """Create table/sets/chains/rules idempotently. Returns an error text
        or None. Safe to call repeatedly (rules are added only when absent)."""
        t = self._table
        steps = [("add", "table", "ip", t)]
        for s in ("blocked", "throttled", "quarantined"):
            steps.append(("add", "set", "ip", t, s,
                          "{ type ipv4_addr; flags timeout; }"))
        for hook in ("input", "forward"):
            steps.append(("add", "chain", "ip", t, hook,
                          "{ type filter hook %s priority -10; policy accept; }"
                          % hook))
        for args in steps:
            proc = self._nft(*args)
            if proc.returncode != 0:
                return (f"{' '.join(args[:3])} failed rc={proc.returncode}: "
                        f"{(proc.stderr or '').strip()[:120]}")
        rules = (("@blocked", "ip saddr @blocked counter drop"),
                 ("@throttled", f"ip saddr @throttled limit rate over "
                                f"{self._pps}/second counter drop"),
                 ("@quarantined", "ip saddr @quarantined counter drop"),
                 ("daddr @quarantined", "ip daddr @quarantined counter drop"))
        for hook in ("input", "forward"):
            listing = self._nft("list", "chain", "ip", t, hook)
            text = listing.stdout or ""
            for marker, rule in rules:
                if marker in text:
                    continue
                proc = self._nft("add", "rule", "ip", t, hook, *rule.split())
                if proc.returncode != 0:
                    return (f"add rule failed rc={proc.returncode}: "
                            f"{(proc.stderr or '').strip()[:120]}")
        self._ready = True
        return None

    # -- Actuator ABC --------------------------------------------------- #

    def execute(self, action: Action) -> ActionResult:
        ttl = action.ttl_minutes
        if ttl is not None and ttl > MAX_TTL_MINUTES:
            return ActionResult(
                ok=False, actuator=self.name,
                detail=f"REJECTED ttl_minutes={ttl} > {MAX_TTL_MINUTES} "
                       f"(G3 enforced at actuator layer)")
        try:
            verdict = self._validator.validate(action)
        except Exception as exc:      # strictness/TTL raises => no crash, no rule
            return ActionResult(ok=False, actuator=self.name,
                                detail=f"G6 gate error: {exc}")
        if verdict is not ValidationVerdict.APPROVED:
            return ActionResult(ok=False, actuator=self.name,
                                detail=f"G6 rejected {action.type.value}")
        atype = (action.type if isinstance(action.type, ActionType)
                 else ActionType(action.type))
        nft_set = _SETS.get(atype)
        if nft_set is None:
            return ActionResult(ok=False, actuator=self.name,
                                detail=f"{atype.value} is not enforceable here")
        try:
            ip = ipaddress.IPv4Address(str(action.target_ip))
        except ValueError:
            return ActionResult(ok=False, actuator=self.name,
                                detail=f"invalid IPv4 target {action.target_ip!r}")
        if (ip.is_unspecified or ip.is_loopback or ip.is_multicast
                or ip.is_link_local or ip.is_reserved):
            return ActionResult(ok=False, actuator=self.name,
                                detail=f"refusing to enforce against {ip}")
        if self.health()["status"] != "healthy":
            return ActionResult(
                ok=False, actuator=self.name,
                detail="nft unavailable — no rule applied (honest failure)")
        if not self._ready:
            err = self.ensure_ruleset()
            if err:
                return ActionResult(ok=False, actuator=self.name,
                                    detail=f"nft setup failed: {err}")
        minutes = int(ttl or DEFAULT_TTL_MINUTES)
        proc = self._nft("add", "element", "ip", self._table, nft_set,
                         "{ %s timeout %dm }" % (ip, minutes))
        if proc.returncode != 0:
            return ActionResult(
                ok=False, actuator=self.name,
                detail=f"nft add failed rc={proc.returncode}: "
                       f"{(proc.stderr or '').strip()[:120]}")
        token = f"{nft_set}:{ip}"
        self._live[token] = {"set": nft_set, "ip": str(ip), "ttl_minutes": minutes}
        return ActionResult(
            ok=True, actuator=self.name,
            detail=f"{atype.value} via nft set {nft_set} for {ip}; "
                   f"kernel auto-expiry in {minutes}m",
            rollback_token=token)

    def rollback(self, token: str) -> ActionResult:
        """Remove one element; idempotent on unknown/expired tokens."""
        self._live.pop(token, None)
        nft_set, _, ip = token.partition(":")
        if nft_set not in _SETS.values():
            return ActionResult(ok=False, actuator=self.name,
                                detail=f"unknown rollback token {token!r}")
        try:
            ipaddress.IPv4Address(ip)
        except ValueError:
            return ActionResult(ok=False, actuator=self.name,
                                detail=f"unknown rollback token {token!r}")
        proc = self._nft("delete", "element", "ip", self._table, nft_set,
                         "{ %s }" % ip)
        err = (proc.stderr or "")
        if proc.returncode == 0:
            return ActionResult(ok=True, actuator=self.name,
                                detail="rolled back")
        if "No such file" in err or "does not exist" in err:
            return ActionResult(ok=True, actuator=self.name,
                                detail="already rolled back or expired")
        return ActionResult(ok=False, actuator=self.name,
                            detail=f"rollback rc={proc.returncode}: {err.strip()[:120]}")

    def flush_all(self) -> ActionResult:
        """Remove EVERY Sentinel enforcement element (``ctl rollback --all``).
        Works from any process because the state lives in the kernel."""
        failed = []
        for s in ("blocked", "throttled", "quarantined"):
            proc = self._nft("flush", "set", "ip", self._table, s)
            err = proc.stderr or ""
            if proc.returncode != 0 and "No such file" not in err:
                failed.append(f"{s}: {err.strip()[:80]}")
        self._live.clear()
        if failed:
            return ActionResult(ok=False, actuator=self.name,
                                detail="; ".join(failed))
        return ActionResult(ok=True, actuator=self.name,
                            detail="all sentinel sets flushed")

    def pending_expiry(self) -> list[str]:
        """Tokens applied by THIS process whose kernel timers may still run."""
        return sorted(self._live)
