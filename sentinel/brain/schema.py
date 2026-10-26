"""SAFE INPUT SCHEMA (§5) — the ONLY fields ever sent to the LLM.

Anti prompt-injection discipline:
  * Whitelist projection — a field exists outbound iff §5 names it.
  * Free-text-bearing sources (source.ref, meta.raw_payload_hash context,
    any raw payload strings/hex dumps/log excerpts) are NEVER projected.
  * signal_types is a PREDEFINED ENUM only; unknown signal strings are
    dropped, never forwarded verbatim.
  * Injection text arriving inside an allowed field's VALUE stays DATA:
    render_prompt() emits it as a JSON string value, never as structure.

This module is the single choke point: every outbound prompt in the codebase
is serialized through build_safe_input()/render_prompt().
"""
from __future__ import annotations

import ipaddress
import json
import re
from dataclasses import dataclass
from typing import Any, Iterable, Mapping, Sequence

# Predefined signal enum = union of the two existing vocabularies:
#   decision-layer families (sentinel.decision.models.SIGNAL_TO_ATTACK keys)
#   + M1 normalizer hints (_EVE_SIGNAL_HINTS values).
# Nothing outside this tuple is ever sent outbound.
SIGNAL_ENUM: frozenset[str] = frozenset({
    "scan", "auth_fail_burst", "beacon_periodic", "dns_tunneling",
    "volume_spike", "ddos_volumetric",
    "suricata_alert", "flow_record", "dns_event", "tls_event",
    "http_event", "ssh_event", "signature_hit",
})

_ALLOWED_KEYS: tuple[str, ...] = (
    "case_id", "src_ip", "dst_ip", "ports", "protocol", "direction",
    "vlan_tag", "baseline_deviation_sigma", "signal_types", "geolocation",
    "asn", "packet_count", "byte_count", "duration_seconds",
    "confidence_score", "timestamps",
)


@dataclass(frozen=True)
class SafeInput:
    """§5 SAFE INPUT SCHEMA record — whitelist-only projection of an incident.

    Every attribute is JSON-primitive or None. No raw payload strings, no
    hex dumps, no free-text log excerpts can exist here by construction.
    """

    case_id: str
    src_ip: str
    dst_ip: str
    ports: dict[str, int | None]
    protocol: str
    direction: str | None
    vlan_tag: str | None
    baseline_deviation_sigma: float | None
    signal_types: tuple[str, ...]
    geolocation: str | None
    asn: int | None
    packet_count: int | None
    byte_count: int | None
    duration_seconds: float | None
    confidence_score: float
    timestamps: dict[str, str]

    def to_dict(self) -> dict[str, Any]:
        """JSON-safe mapping containing ONLY the §5 keys (test-pinned)."""
        return {
            "case_id": self.case_id,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "ports": dict(self.ports),
            "protocol": self.protocol,
            "direction": self.direction,
            "vlan_tag": self.vlan_tag,
            "baseline_deviation_sigma": self.baseline_deviation_sigma,
            "signal_types": list(self.signal_types),
            "geolocation": self.geolocation,
            "asn": self.asn,
            "packet_count": self.packet_count,
            "byte_count": self.byte_count,
            "duration_seconds": self.duration_seconds,
            "confidence_score": self.confidence_score,
            "timestamps": dict(self.timestamps),
        }


_TOKEN = re.compile(r"[A-Za-z0-9_.:-]{1,64}")
_CASE_ID = re.compile(r"[A-Za-z0-9_.:-]{1,128}")


def _clean_ip(value: Any) -> str:
    """Packet-derived address fields must BE addresses, else they are dropped
    (an attacker-influenced log field must not carry prose to the model)."""
    try:
        return str(ipaddress.ip_address(str(value).strip()))
    except ValueError:
        return ""


def _clean_token(value: Any, default: str | None) -> str | None:
    if value is None:
        return default
    text = str(value)
    return text if _TOKEN.fullmatch(text) else default


def _known_signals(signals: Iterable[str]) -> tuple[str, ...]:
    """Keep only enum members, preserving order, deduplicated."""
    seen: dict[str, None] = {}
    for s in signals:
        if s in SIGNAL_ENUM and s not in seen:
            seen[s] = None
    return tuple(seen)


def build_safe_input(
    case_id: str,
    alerts: Sequence[Any],
    *,
    direction: str | None = None,
    geolocation: str | None = None,
    asn: int | None = None,
    baseline_deviation_sigma: float | None = None,
    first_seen: str | None = None,
) -> SafeInput:
    """Project incident/alerts into the §5 whitelist — THE outbound choke point.

    `alerts` are sentinel.models.Alert instances (duck-typed read-only).
    Fields §5 does not name (source.ref, raw_payload_hash, hostnames…) are
    simply never read. Unknown signal strings are dropped.
    """
    if not alerts:
        raise ValueError("build_safe_input requires at least one alert")
    first = alerts[0]
    meta = getattr(first, "meta", None)
    ts_values = sorted({str(getattr(a, "ts", "")) for a in alerts if a.ts})
    timestamps: dict[str, str] = {"first_alert": ts_values[0] if ts_values else ""}
    if first_seen:
        timestamps["incident_first_seen"] = str(first_seen)

    ports: dict[str, int | None] = {
        "src_port": int(getattr(first, "src_port", 0) or 0),
        "dst_port": int(getattr(first, "dst_port", 0) or 0),
    }

    return SafeInput(
        case_id=(str(case_id) if _CASE_ID.fullmatch(str(case_id))
                 else "invalid-case-id"),
        src_ip=_clean_ip(getattr(first, "src_ip", "")),
        dst_ip=_clean_ip(getattr(first, "dst_ip", "")),
        ports=ports,
        protocol=_clean_token(getattr(first, "protocol", ""), "unknown") or "unknown",
        direction=_clean_token(direction, None),
        vlan_tag=_clean_token(getattr(first, "vlan", None), None),
        baseline_deviation_sigma=baseline_deviation_sigma,
        signal_types=_known_signals(
            s for a in alerts for s in getattr(a, "signals", ())),
        geolocation=geolocation,
        asn=asn,
        packet_count=getattr(meta, "packet_count", None),
        byte_count=getattr(meta, "byte_count", None),
        duration_seconds=getattr(meta, "duration_seconds", None),
        confidence_score=float(max(getattr(a, "confidence_raw", 0.0)
                                   for a in alerts)),
        timestamps=timestamps,
    )


def render_prompt(safe_input: SafeInput) -> str:
    """Stable JSON rendering — the verbatim outbound prompt payload.

    Injection text inside any field VALUE remains a JSON string value
    (data), never parsed as instruction structure.
    """
    blob = json.dumps(safe_input.to_dict(), sort_keys=True,
                      separators=(",", ":"), ensure_ascii=False)
    return blob


def allowed_keys() -> tuple[str, ...]:
    """The §5 key whitelist, pinned for tests and audit review."""
    return _ALLOWED_KEYS
