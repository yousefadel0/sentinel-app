"""LLM output contract (§5a) — JSON-schema validation ONLY.

Accepted shape (exact key set; extra keys rejected):
    attack_type         ∈ {scan, brute_force, ddos_volumetric, c2_beacon,
                           dns_tunneling}
    confidence          float 0..1
    severity            int 1..5
    affected_assets     list[str]
    recommended_action  ∈ ALLOWED_ACTIONS v1 strings
    ttl_minutes         int ≤60 (required iff action is aggressive;
                          must be null otherwise)
    rationale           str, bounded length

Any violation raises BrainOutputError. The caller (triage_incident) converts
every failure into a silent rule-based fallback (P4) — no error text ever
reaches SOC output.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Mapping

ATTACK_TYPES = ("scan", "brute_force", "ddos_volumetric",
                "c2_beacon", "dns_tunneling")
ALLOWED_ACTIONS = ("notify_only", "throttle_src", "block_ip_temp",
                   "quarantine_asset", "escalate_human")
AGGRESSIVE_ACTIONS = frozenset({"throttle_src", "block_ip_temp",
                                "quarantine_asset"})
MAX_RATIONALE_CHARS = 2000
MAX_ASSETS = 64

_REQUIRED_KEYS = ("attack_type", "confidence", "severity",
                  "affected_assets", "recommended_action", "rationale")


class BrainOutputError(ValueError):
    """LLM output failed the §5a schema. Message stays internal (P4)."""


@dataclass(frozen=True)
class TriageResult:
    """Validated LLM classification — advisory input to the engine only."""

    attack_type: str
    confidence: float
    severity: int
    affected_assets: tuple[str, ...]
    recommended_action: str
    ttl_minutes: int | None
    rationale: str


def _fail(msg: str) -> None:
    raise BrainOutputError(msg)


def parse_output(raw: str) -> TriageResult:
    """Validate raw LLM text against the §5a contract; return TriageResult.

    Raises BrainOutputError on ANY deviation (malformed JSON, wrong types,
    extra keys, oversized strings, enum violations, out-of-range numbers).
    """
    try:
        obj = json.loads(raw)
    except (json.JSONDecodeError, ValueError):
        _fail("output is not valid JSON")
    if not isinstance(obj, Mapping):
        _fail("output must be a JSON object")

    for key in _REQUIRED_KEYS:
        if key not in obj:
            _fail(f"missing required key: {key}")
    allowed = set(_REQUIRED_KEYS) | {"ttl_minutes"}
    extras = sorted(set(obj) - allowed)
    if extras:
        _fail(f"unexpected keys: {', '.join(extras)}")

    attack_type = obj["attack_type"]
    if not isinstance(attack_type, str) or attack_type not in ATTACK_TYPES:
        _fail("attack_type violates enum")

    confidence = obj["confidence"]
    if isinstance(confidence, bool) or not isinstance(confidence, (int, float)) \
            or not 0.0 <= float(confidence) <= 1.0:
        _fail("confidence must be a number in [0,1]")

    severity = obj["severity"]
    if isinstance(severity, bool) or not isinstance(severity, int) \
            or not 1 <= severity <= 5:
        _fail("severity must be an integer in [1,5]")

    assets = obj["affected_assets"]
    if not isinstance(assets, list) or len(assets) > MAX_ASSETS:
        _fail("affected_assets must be a bounded list")
    for a in assets:
        if not isinstance(a, str):
            _fail("affected_assets entries must be strings")

    action = obj["recommended_action"]
    if not isinstance(action, str) or action not in ALLOWED_ACTIONS:
        _fail("recommended_action violates ALLOWED_ACTIONS")

    ttl = obj.get("ttl_minutes")
    if ttl is not None:
        if isinstance(ttl, bool) or not isinstance(ttl, int) or ttl < 1 \
                or ttl > 60:  # G3 ceiling
            _fail("ttl_minutes must be an integer in [1,60]")
        if action not in AGGRESSIVE_ACTIONS:
            _fail("ttl_minutes only allowed with aggressive actions")
    elif action in AGGRESSIVE_ACTIONS:
        _fail(f"ttl_minutes required for {action}")

    rationale = obj["rationale"]
    if not isinstance(rationale, str) or len(rationale) > MAX_RATIONALE_CHARS:
        _fail("rationale must be a bounded string")

    return TriageResult(
        attack_type=attack_type,
        confidence=float(confidence),
        severity=severity,
        affected_assets=tuple(assets),
        recommended_action=action,
        ttl_minutes=ttl,
        rationale=rationale,
    )
