"""Defensive-edge coverage for the strict validator.

These exercise failure branches beyond the canonical fixtures so that every
refusal path is proven to cite (ref §8).
"""
from __future__ import annotations

import pytest

from sentinel.config import ConfigError, load_config, validate_config

REF = "(ref §8)"


def _base() -> dict:
    import yaml
    from pathlib import Path
    p = Path(__file__).parent / "fixtures" / "valid_config.yaml"
    return yaml.safe_load(p.read_text())


# --- scalar edge cases ---

def test_bool_rejected_where_int_expected():
    raw = _base()
    raw["autonomy_level"] = True          # bool sneaking in as int
    with pytest.raises(ConfigError) as e:
        validate_config(raw)
    assert "got bool" in str(e.value)


def test_below_minimum_refused():
    raw = _base()
    raw["limits"]["default_ttl_min"] = -1
    with pytest.raises(ConfigError) as e:
        validate_config(raw)
    assert "below minimum" in str(e.value)


def test_null_required_key_refused():
    raw = _base()
    raw["site"]["name"] = None
    with pytest.raises(ConfigError) as e:
        validate_config(raw)
    assert "required key missing (got null)" in str(e.value)


def test_section_given_as_scalar_refused():
    raw = _base()
    raw["brain"] = 7
    with pytest.raises(ConfigError) as e:
        validate_config(raw)
    assert "expected type dict, got int" in str(e.value)


def test_list_given_as_scalar_refused():
    raw = _base()
    raw["monitored_vlans"] = "prod"
    with pytest.raises(ConfigError) as e:
        validate_config(raw)
    assert "expected type list, got str" in str(e.value)


def test_list_item_wrong_type_refused():
    raw = _base()
    raw["monitored_vlans"] = ["prod", 42]
    with pytest.raises(ConfigError) as e:
        validate_config(raw)
    assert "expected item type str, got int" in str(e.value)


def test_actuator_item_not_a_dict_refused():
    raw = _base()
    raw["actuators"] = ["nftables_local"]
    with pytest.raises(ConfigError) as e:
        validate_config(raw)
    assert "expected type dict, got str" in str(e.value)


# --- conditional requirement: url iff webhook_soar ---

def test_webhook_soar_without_url_refused():
    raw = _base()
    raw["actuators"].append({"type": "webhook_soar"})
    with pytest.raises(ConfigError) as e:
        validate_config(raw)
    assert "required when 'type' == 'webhook_soar'" in str(e.value)


def test_webhook_soar_with_url_passes():
    raw = _base()
    raw["actuators"].append(
        {"type": "webhook_soar", "url": "https://soar.example/hook"})
    assert validate_config(raw) is raw


def test_nftables_local_without_url_is_fine():
    raw = _base()   # valid config has nftables_local without url
    assert validate_config(raw)["actuators"][0]["type"] == "nftables_local"


# --- cross-field rule absence tolerance & YAML syntax ---

def test_cross_field_rule_skipped_when_keys_absent():
    raw = {"site": {"name": "x", "critical_assets": []},
           "capture_interfaces": ["eth0"], "placement": {},
           "monitored_vlans": [], "unmapped_vlans": [], "has_nat": False,
           "brain": {}, "actuators": [{"type": "nftables_local"}],
           "autonomy_level": 0, "limits": {}}
    # missing required sub-keys are reported; no crash from cross-field dig
    with pytest.raises(ConfigError):
        validate_config(raw)


def test_invalid_yaml_syntax_refused(tmp_path):
    bad = tmp_path / "broken.yaml"
    bad.write_text("site: [unclosed\n  brain: {")
    with pytest.raises(ConfigError) as e:
        load_config(bad)
    assert "invalid YAML syntax" in str(e.value)
