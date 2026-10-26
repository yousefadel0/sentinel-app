"""Boot-time bind validation for the Minimal Ops UI (M7).

This is the M0-deferred check landing now (§8 comment on `ops_ui.bind`:
"plain string for M0 (M7 validates)"). Two DIMENSIONS are validated, and
they are deliberately different kinds of rule (DP1):

* Port allowlist  — OPERATOR POLICY. The operator chooses WHICH ports via
  the required config key ``ops_ui.allowed_ports`` (list of ints). Invalid
  shape/values refuse boot fail-closed with the offending value + valid
  shape message, §8 style.

* Loopback-only   — HARD SECURITY INVARIANT. The operator never chooses
  WHERE it listens. Host must be inside 127.0.0.0/8 or exactly [::1].
  Any other address (0.0.0.0, ::, routable unicast, hostnames) refuses
  boot ALWAYS, regardless of any config value. This invariant is NOT
  overridable via configuration by construction — there is no config key
  that could relax it.

Both checks run at boot even when ``enabled: false``: §8 configs are
validated whole; a config that COULD not be served safely is refused,
not deferred until first serve.
"""
from __future__ import annotations

import ipaddress

from sentinel.config.loader import ConfigError

#: Hard security invariant (DP1): loopback ONLY. Not operator-overridable;
#: there is deliberately no config key that can widen this set.
_LOOPBACK_NETS = (
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
)


def validate_bind(bind: object, allowed_ports: object,
                  allow_routable: bool = False) -> int:
    """Validate ``ops_ui.bind`` + ``allowed_ports``; return the port.

    Raises ConfigError naming ``ops_ui.bind`` / ``ops_ui.allowed_ports``
    with the offending value and the valid shape, per §8 refusal style.
    ``allow_routable`` exists ONLY as a test seam proving the invariant
    cannot be relaxed via config — it still refuses (see tests).
    """
    if allow_routable:  # pragma: no cover - documented non-relaxation
        raise ConfigError(
            "ops_ui.bind: loopback-only is a hard security invariant and "
            "cannot be overridden by any configuration value")
    if not isinstance(allowed_ports, list) or not all(
        isinstance(p, int) and not isinstance(p, bool) for p in allowed_ports
    ):
        raise ConfigError(
            f"ops_ui.allowed_ports: invalid value {allowed_ports!r}; "
            "expected a list of integers, e.g. allowed_ports: [8080, 8081]"
        )
    if not allowed_ports:
        raise ConfigError(
            "ops_ui.allowed_ports: empty list; expected at least one "
            "permitted port, e.g. allowed_ports: [8080]"
        )

    if not isinstance(bind, str):
        raise ConfigError(
            f"ops_ui.bind: invalid value {bind!r}; expected \"host:port\" "
            "with host loopback-only (127.0.0.0/8 or [::1])"
        )

    # Bracketed IPv6 form first: "[::1]:8080".
    if bind.startswith("["):
        close = bind.find("]")
        if close == -1 or not bind[close + 1:].startswith(":"):
            raise ConfigError(
                f"ops_ui.bind: malformed value {bind!r}; expected "
                "\"[::1]:<port>\" with host loopback-only"
            )
        host_part, port_part = bind[1:close], bind[close + 2:]
    else:
        host_part, sep, port_part = bind.rpartition(":")
        if not sep:
            raise ConfigError(
                f"ops_ui.bind: malformed value {bind!r}; expected "
                "\"host:port\", e.g. \"127.0.0.1:8080\""
            )

    try:
        port = int(port_part)
    except ValueError:
        port = -1
    if not (1024 <= port <= 65535):
        raise ConfigError(
            f"ops_ui.bind: port {port_part!r} out of range; expected an "
            "integer in 1024..65535 (unprivileged), matching one entry of "
            f"ops_ui.allowed_ports {allowed_ports!r}"
        )
    if port not in allowed_ports:
        raise ConfigError(
            f"ops_ui.bind: port {port_part!r} not in ops_ui.allowed_ports "
            f"{allowed_ports!r} (operator policy — choose a permitted port)"
        )

    try:
        addr = ipaddress.ip_address(host_part)
    except ValueError as exc:
        raise ConfigError(
            f"ops_ui.bind: host {host_part!r} is not a literal IP address "
            f"({exc}); the Ops UI listens on loopback IPs only, never "
            "hostnames"
        ) from None
    if not any(addr in net for net in _LOOPBACK_NETS):
        raise ConfigError(
            f"ops_ui.bind: host {host_part!r} is not loopback; the Ops UI "
            "listens on 127.0.0.0/8 or [::1] ONLY (hard invariant, never "
            "exposed to routable networks)"
        )
    return port
