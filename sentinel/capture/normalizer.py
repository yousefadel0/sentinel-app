"""Normalizer — the single decision point from raw events to §4 Alerts.

Every adapter (Suricata eve.json, Zeek conn/dns/ssl/notice, future sources)
funnels through :func:`normalize` here. Confidence-tier assignment is a
CENTRALIZED mapping (:data:`ADAPTER_TIERS` / :func:`assign_tier`) so the M2
behavioral-tier extension touches exactly one place — never per-source
if-statements scattered across adapters.

P6 audit discipline: raw evidence crosses this boundary only as a sha256
digest; payloads are never copied into the Alert.
"""
from __future__ import annotations

import hashlib
import uuid
from typing import Any, Mapping

from sentinel.models import (
    Alert,
    AlertMeta,
    AssetHint,
    ConfidenceTier,
    SourceRef,
)

#: Centralized tier map — THE single decision point for tier assignment.
#: Wire-evidence-only adapters are Tier A by doctrine (§3). M2 will extend
#: THIS table (e.g. behavioral => B); no source module needs rewriting.
ADAPTER_TIERS: dict[str, ConfidenceTier] = {
    "eve_json": ConfidenceTier.A,
    "zeek_conn": ConfidenceTier.A,
    "zeek_dns": ConfidenceTier.A,
    "zeek_ssl": ConfidenceTier.A,
    "zeek_notice": ConfidenceTier.A,
    # Phase 3/5: behavioral detectors are wire+behavioral (B); SIEM-fed
    # identity evidence is external (C) and can never auto-act (§3).
    "behavioral": ConfidenceTier.B,
    "wazuh_inbound": ConfidenceTier.C,
}

#: eve.json event_type values worth surfacing as signal hints (folded item 1).
_EVE_SIGNAL_HINTS: dict[str, str] = {
    "alert": "suricata_alert",
    "flow": "flow_record",
    "dns": "dns_event",
    "tls": "tls_event",
    "http": "http_event",
    "ssh": "ssh_event",
}


def assign_tier(adapter: str) -> ConfidenceTier:
    """Return the tier for *adapter* via the centralized ADAPTER_TIERS map.

    Raises KeyError for unknown adapters — fail loudly rather than silently
    guessing a tier (P5 spirit; an unmapped provenance must be added to the
    table explicitly).
    """
    return ADAPTER_TIERS[adapter]


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def normalize(
    raw: Mapping[str, Any],
    *,
    adapter: str,
    ref: str,
    vlan: str | None = None,
    asset_hint: AssetHint | None = None,
    confidence_raw: float = 0.5,
    signals: tuple[str, ...] = (),
) -> Alert:
    """Normalize one raw source event into a unified §4 :class:`Alert`.

    Parameters
    ----------
    raw:
        The parsed source record (eve.json object or Zeek TSV row dict).
        Used read-only; never stored — only its sha256 digest is kept.
    adapter:
        Provenance identifier, e.g. ``"eve_json"``, ``"zeek_conn"``.
    ref:
        Adapter-specific locator, e.g. ``"sample_eve.jsonl#12"``.
    vlan:
        VLAN tag resolved by the adapter against config (None = untagged).
    asset_hint:
        Best-known asset identity from site.critical_assets lookup.
    confidence_raw:
        Source-level confidence in [0, 1]; tier comes from ADAPTER_TIERS.
    signals:
        Base signal labels; eve event_type hints are appended here.

    Returns
    -------
    Alert
        Fully-populated §4 model with ALL fields set (vlan may be None for
        untagged traffic; meta carries counts when the source provides them).

    Notes
    -----
    Folded item 1: eve.json ``event_type`` is mapped into BOTH a signal hint
    (``suricata_alert``, ``dns_event``, ...) and ``meta``-adjacent provenance
    via the source ref, so M3 playbooks can key off it without re-parsing.
    """
    tier = assign_tier(adapter)

    extra_signals: list[str] = []
    if adapter == "eve_json":
        event_type = raw.get("event_type")
        hint = _EVE_SIGNAL_HINTS.get(str(event_type))
        if hint:
            extra_signals.append(hint)
        if isinstance(raw.get("alert"), Mapping):
            extra_signals.append("signature_hit")

    all_signals = tuple(dict.fromkeys((*signals, *extra_signals)))

    alert_meta = AlertMeta(
        packet_count=raw.get("packet_count") if "packet_count" in raw else None,
        byte_count=raw.get("bytes") if "bytes" in raw else None,
        duration_seconds=(
            float(raw["flow"]["duration_seconds"])
            if isinstance(raw.get("flow"), Mapping) and "duration_seconds" in raw["flow"]
            else None
        ),
        raw_payload_hash=_sha256(ref),
    )

    return Alert(
        alert_id=str(uuid.uuid4()),
        ts=str(raw.get("timestamp") or raw.get("ts") or ""),
        source=SourceRef(adapter=adapter, ref=ref),
        src_ip=str(raw.get("src_ip") or raw.get("id.orig_h") or ""),
        dst_ip=str(raw.get("dest_ip") or raw.get("id.resp_h") or ""),
        src_port=int(raw.get("src_port", raw.get("id.orig_p", 0)) or 0),
        dst_port=int(raw.get("dest_port", raw.get("id.resp_p", 0)) or 0),
        protocol=str(raw.get("proto", raw.get("proto", "")).lower() or "unknown"),
        vlan=vlan,
        asset_hint=asset_hint or AssetHint(),
        signals=all_signals,
        confidence_raw=float(confidence_raw),
        confidence_tier=tier,
        meta=alert_meta,
    )
