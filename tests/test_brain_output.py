"""Fuzzed-output suite (§5a) — every malformed shape rejected safely."""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sentinel.brain import BrainOutputError, parse_output  # noqa: E402


def _valid() -> dict:
    return {
        "attack_type": "c2_beacon",
        "confidence": 0.91,
        "severity": 4,
        "affected_assets": ["10.0.0.4"],
        "recommended_action": "block_ip_temp",
        "ttl_minutes": 30,
        "rationale": "periodic beaconing to known-bad ASN",
    }


def test_valid_output_parses():
    r = parse_output(json.dumps(_valid()))
    assert r.attack_type == "c2_beacon"
    assert r.severity == 4
    assert r.ttl_minutes == 30
    assert r.affected_assets == ("10.0.0.4",)


def test_malformed_json_rejected():
    for raw in ("", "{", "not json", "[1,2]", '"str"', "null"):
        with pytest.raises(BrainOutputError):
            parse_output(raw)


def test_missing_required_key_rejected():
    obj = _valid()
    del obj["rationale"]
    with pytest.raises(BrainOutputError, match="missing required key"):
        parse_output(json.dumps(obj))


def test_extra_keys_rejected():
    obj = _valid()
    obj["command"] = "rm -rf /"          # injection-shaped extra key
    obj["ignore_previous_instructions"] = True
    with pytest.raises(BrainOutputError, match="unexpected keys"):
        parse_output(json.dumps(obj))


@pytest.mark.parametrize("bad", [
    "scan-not-in-enum", "", 7, None, ["scan"], {"a": 1},
])
def test_attack_type_enum_violations(bad):
    obj = _valid()
    obj["attack_type"] = bad
    with pytest.raises(BrainOutputError, match="attack_type"):
        parse_output(json.dumps(obj))


@pytest.mark.parametrize("bad", [-0.1, 1.01, "0.9", True, None, [0.5]])
def test_confidence_range_and_types(bad):
    obj = _valid()
    obj["confidence"] = bad
    with pytest.raises(BrainOutputError, match="confidence"):
        parse_output(json.dumps(obj))


@pytest.mark.parametrize("bad", [0, 6, 2.5, "4", True, None])
def test_severity_must_be_int_1_to_5(bad):
    obj = _valid()
    obj["severity"] = bad
    with pytest.raises(BrainOutputError, match="severity"):
        parse_output(json.dumps(obj))


def test_affected_assets_type_and_bounds():
    obj = _valid()
    obj["affected_assets"] = "10.0.0.4"          # not a list
    with pytest.raises(BrainOutputError, match="bounded list"):
        parse_output(json.dumps(obj))
    obj["affected_assets"] = [123]
    with pytest.raises(BrainOutputError, match="strings"):
        parse_output(json.dumps(obj))
    obj["affected_assets"] = ["a"] * 65
    with pytest.raises(BrainOutputError, match="bounded list"):
        parse_output(json.dumps(obj))


@pytest.mark.parametrize("bad", [
    "notify_only-typo", "", 3, None, ["block_ip_temp"], "rm -rf /",
])
def test_recommended_action_enum_violations(bad):
    obj = _valid()
    obj["recommended_action"] = bad
    with pytest.raises(BrainOutputError, match="ALLOWED_ACTIONS"):
        parse_output(json.dumps(obj))


@pytest.mark.parametrize("action", ["throttle_src", "block_ip_temp",
                                    "quarantine_asset"])
def test_ttl_required_for_aggressive_actions(action):
    obj = _valid()
    obj["recommended_action"] = action
    del obj["ttl_minutes"]
    with pytest.raises(BrainOutputError, match="ttl_minutes required"):
        parse_output(json.dumps(obj))


def test_ttl_ceiling_60_g3():
    obj = _valid()
    obj["ttl_minutes"] = 61
    with pytest.raises(BrainOutputError, match=r"ttl_minutes must be"):
        parse_output(json.dumps(obj))
    obj["ttl_minutes"] = 0
    with pytest.raises(BrainOutputError):
        parse_output(json.dumps(obj))
    obj["ttl_minutes"] = True          # bool masquerading as int
    with pytest.raises(BrainOutputError):
        parse_output(json.dumps(obj))


def test_ttl_disallowed_for_non_aggressive():
    obj = _valid()
    obj["recommended_action"] = "notify_only"
    with pytest.raises(BrainOutputError, match="only allowed"):
        parse_output(json.dumps(obj))


def test_ttl_optional_null_for_notify_and_escalate():
    for action in ("notify_only", "escalate_human"):
        obj = _valid()
        obj["recommended_action"] = action
        obj["ttl_minutes"] = None
        r = parse_output(json.dumps(obj))
        assert r.ttl_minutes is None


def test_oversized_rationale_rejected():
    obj = _valid()
    obj["rationale"] = "x" * 2001
    with pytest.raises(BrainOutputError, match="bounded string"):
        parse_output(json.dumps(obj))


def test_error_message_is_clear_but_internal():
    """Clear error text exists — but triage never leaks it to SOC output."""
    with pytest.raises(BrainOutputError) as ei:
        parse_output("{oops")
    assert "JSON" in str(ei.value)
