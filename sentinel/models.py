"""Core data model (§4) and shared result types.

The unified Alert is the single currency between adapters, correlator,
decision engine and audit store. NEVER raw payloads — hashes/summaries only.
"""
from __future__ import annotations

import enum
import hashlib
import json
from dataclasses import asdict, dataclass, field
from typing import Any


class ConfidenceTier(str, enum.Enum):
    """§3 confidence tiers — evidence provenance drives autonomy ceilings."""

    A = "A"  # wire evidence only            -> auto-act at score >= 0.90
    B = "B"  # wire + behavioral              -> auto-throttle >= 0.95, else human
    C = "C"  # identity/external-fed          -> NEVER auto-act; alert/human only


class ActionType(str, enum.Enum):
    """ALLOWED_ACTIONS v1 (§5). Nothing outside this set may ever be executed."""

    NOTIFY_ONLY = "notify_only"
    THROTTLE_SRC = "throttle_src"
    BLOCK_IP_TEMP = "block_ip_temp"
    QUARANTINE_ASSET = "quarantine_asset"
    ESCALATE_HUMAN = "escalate_human"


@dataclass(frozen=True)
class SourceRef:
    """Provenance of an alert: which adapter produced it, with a locator."""

    adapter: str            # eve_json | zeek_conn | zeek_dns | <future>
    ref: str                # adapter-specific pointer (file+line, flow uid, ...)


@dataclass(frozen=True)
class AssetHint:
    """Best-known asset identity for src/dst (resolved by later milestones)."""

    resolved_hostname: str | None = None
    asset_id: str | None = None
    criticality: str | None = None  # critical|high|medium|low


@dataclass(frozen=True)
class AlertMeta:
    """Aggregates + evidence hash. Raw payloads never cross the boundary."""

    packet_count: int | None = None
    byte_count: int | None = None
    duration_seconds: float | None = None
    raw_payload_hash: str | None = None   # sha256 hex of raw evidence


@dataclass(frozen=True)
class Alert:
    """Unified alert model — exact §4 field set.

    Fields: alert_id, ts(iso8601), source{adapter,ref}, src_ip, dst_ip,
    src_port, dst_port, protocol, vlan, asset_hint{...}, signals[],
    confidence_raw 0..1, confidence_tier A|B|C, meta{...}
    """

    alert_id: str
    ts: str                                   # ISO-8601 timestamp
    source: SourceRef
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str                             # tcp|udp|icmp|...
    vlan: str | None                          # None when untagged/unmapped
    asset_hint: AssetHint
    signals: tuple[str, ...]                  # "scan", "auth_fail_burst", ...
    confidence_raw: float                     # 0.0 .. 1.0
    confidence_tier: ConfidenceTier           # A | B | C
    meta: AlertMeta

    def __post_init__(self) -> None:
        if not 0.0 <= self.confidence_raw <= 1.0:
            raise ValueError(f"confidence_raw must be in [0,1], got {self.confidence_raw}")
        if isinstance(self.confidence_tier, str):
            # tolerate plain strings from adapters by coercing to the enum
            object.__setattr__(self, "confidence_tier", ConfidenceTier(self.confidence_tier))

    def to_dict(self) -> dict[str, Any]:
        """JSON-safe projection for audit/logging (no raw payloads by design)."""
        return asdict(self)

    def evidence_digest(self) -> str:
        """Stable sha256 over the alert's own content — audit-chain seed."""
        blob = json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(blob.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class Action:
    """A proposed protective action (deterministic engine or playbook output)."""

    type: ActionType
    target_ip: str | None = None
    ttl_minutes: int | None = None            # G3: <= 60 when set
    params: dict[str, Any] = field(default_factory=dict)  # rate_pps, scope, reason...
    rationale: str = ""


@dataclass(frozen=True)
class ActionResult:
    """Outcome of Actuator.execute() (ABC #2 contract)."""

    ok: bool
    actuator: str
    detail: str = ""
    rollback_token: str | None = None         # opaque handle for rollback()
