"""Evidence-derived confidence — no invented constants.

Every function documents exactly which real field it reads and what the
mapping is, so a score can always be explained from the raw evidence. When a
sensor supplies nothing usable the result is a clearly named FLOOR
(``UNKNOWN_FLOOR``), never a number that looks like a measurement.
"""
from __future__ import annotations

from typing import Any, Mapping

#: Used only when the source provides no usable field at all.
UNKNOWN_FLOOR = 0.40

# Suricata alert.severity: 1 = high, 2 = medium, 3 = low (rule author's rating).
_SURICATA_SEVERITY = {1: 0.85, 2: 0.70, 3: 0.55}
# Rule metadata "confidence" (ET Pro style) when the sensor emits metadata.
_META_CONFIDENCE = {"high": 0.90, "medium": 0.70, "low": 0.50}

#: Zeek notice.log `note` values that are Zeek's own attack analytics, mapped
#: to the signal vocabulary the decision engine understands.
ZEEK_NOTICE_SIGNALS: dict[str, str] = {
    "Scan::Port_Scan": "scan",
    "Scan::Address_Scan": "scan",
    "Scan::Random_Scan": "scan",
    "SSH::Password_Guessing": "auth_fail_burst",
    "FTP::Bruteforcing": "auth_fail_burst",
    "HTTP::Password_Guessing": "auth_fail_burst",
    "DNS::External_Name": "dns_tunneling",
}
ZEEK_NOTICE_CONFIDENCE = 0.80          # Zeek raised it from observed behavior


def _clamp(v: float) -> float:
    return round(min(0.99, max(0.05, float(v))), 4)


def suricata_confidence(raw: Mapping[str, Any]) -> float:
    """Confidence of one Suricata ``alert`` event.

    Order of preference:
    1. an explicit numeric ``alert.confidence`` in [0, 1] (test generators and
       some custom pipelines);
    2. rule metadata ``confidence`` (High / Medium / Low);
    3. rule ``severity`` (1 -> 0.85, 2 -> 0.70, 3 -> 0.55);
    4. ``UNKNOWN_FLOOR``.
    """
    alert = raw.get("alert")
    if not isinstance(alert, Mapping):
        return UNKNOWN_FLOOR
    explicit = alert.get("confidence")
    if isinstance(explicit, (int, float)) and not isinstance(explicit, bool) \
            and 0.0 <= float(explicit) <= 1.0:
        return _clamp(explicit)
    meta = alert.get("metadata")
    if isinstance(meta, Mapping):
        vals = meta.get("confidence")
        if isinstance(vals, (list, tuple)) and vals:
            mapped = _META_CONFIDENCE.get(str(vals[0]).strip().lower())
            if mapped is not None:
                return _clamp(mapped)
    sev = alert.get("severity")
    if isinstance(sev, int) and not isinstance(sev, bool) and sev in _SURICATA_SEVERITY:
        return _clamp(_SURICATA_SEVERITY[sev])
    return UNKNOWN_FLOOR


def wazuh_confidence(rule_level: Any) -> float:
    """Wazuh ``rule.level`` (0-15) -> 0.40 + 0.04 x level, capped at 0.95."""
    if isinstance(rule_level, int) and not isinstance(rule_level, bool) \
            and 0 <= rule_level <= 15:
        return _clamp(min(0.95, 0.40 + 0.04 * rule_level))
    return UNKNOWN_FLOOR


def noisy_or(confidences: list[float]) -> float:
    """P(at least one independent source is right) = 1 - prod(1 - c)."""
    p = 1.0
    for c in confidences:
        p *= 1.0 - min(0.99, max(0.0, c))
    return _clamp(1.0 - p)
