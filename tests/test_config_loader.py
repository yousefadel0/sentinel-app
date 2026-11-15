"""GATE (a): invalid config refuses boot with clear error message.

Every failure class must raise ConfigError whose message contains:
  * the offending key/path,
  * the list of valid keys,
  * the literal reference "(ref §8)".
Plus happy-path load of the §8 sketch verbatim.
"""
from __future__ import annotations

import pytest

from sentinel.config import ConfigError, load_config, validate_config

REF = "(ref §8)"

# fixture file -> (substring expected in the error message)
FAILURE_CLASSES = {
    "unknown_top_key.yaml":            ("extra_key", "site,", REF),
    "unknown_nested_key.yaml":         ("autonomy_lvl", "autonomy_level", REF),
    "missing_required_section.yaml":   ("placement", "required section missing", REF),
    "bad_enum_value.yaml":             ("asymmetric_risk", "high, medium, low", REF),
    "wrong_type.yaml":                 ("has_nat", "expected type bool", REF),
    "empty_capture_interfaces.yaml":   ("capture_interfaces", "at least 1 item", REF),
    "ttl_above_60.yaml":               ("default_ttl_min", "above maximum 60", REF),
    "cutoff_gt_timeout.yaml":          ("cross-field violation", "hard_cutoff_s", REF),
    "bad_ipv4_format.yaml":            ("critical_assets[0].ip", "not a valid IPv4", REF),
    "missing_actuator_url.yaml":       ("url", "webhook_soar", REF),
    "autonomy_out_of_range.yaml":      ("autonomy_level", "above maximum 3", REF),
}


def test_valid_config_loads_clean(valid_config_path):
    cfg = load_config(valid_config_path)
    assert cfg["site"]["name"] == "customer-A"
    assert cfg["autonomy_level"] == 0
    assert cfg["limits"]["default_ttl_min"] == 30


def test_protected_ip_list_validates_each_address(valid_config_path):
    import yaml
    raw = yaml.safe_load(valid_config_path.read_text())
    raw["site"]["protected_ips"] = ["10.0.0.1", "not-an-ip"]
    with pytest.raises(ConfigError, match=r"protected_ips\[1\].*valid IPv4"):
        validate_config(raw)


@pytest.mark.parametrize("fixture_name", sorted(FAILURE_CLASSES))
def test_invalid_config_refuses_boot_with_clear_error(invalid_dir, fixture_name):
    path = invalid_dir / fixture_name
    with pytest.raises(ConfigError) as excinfo:
        load_config(path)
    message = str(excinfo.value)
    for expected in FAILURE_CLASSES[fixture_name]:
        assert expected in message, (
            f"{fixture_name}: error message missing {expected!r}\n--- got ---\n{message}"
        )


def test_missing_file_names_the_path(tmp_path):
    with pytest.raises(ConfigError) as excinfo:
        load_config(tmp_path / "nope.yaml")
    assert "config file not found" in str(excinfo.value)


def test_non_mapping_top_level_refuses():
    with pytest.raises(ConfigError) as excinfo:
        validate_config(["not", "a", "mapping"])
    assert "(ref §8)" in str(excinfo.value)


def test_all_errors_aggregated_not_first_only(tmp_valid_config):
    text = tmp_valid_config.read_text()
    # two independent violations: unknown key + bad enum
    mutated = text.replace(
        "asymmetric_risk: medium", "asymmetric_risk: extreme"
    ) + "\nsurprise_key: 1\n"
    tmp_valid_config.write_text(mutated)
    with pytest.raises(ConfigError) as excinfo:
        load_config(tmp_valid_config)
    message = str(excinfo.value)
    assert "surprise_key" in message and "asymmetric_risk" in message


def test_error_lists_valid_keys_for_offended_level(valid_config_path):
    import yaml
    raw = yaml.safe_load(valid_config_path.read_text())
    raw["brain"]["timeouts"] = 99          # typo'd nested key
    with pytest.raises(ConfigError) as excinfo:
        validate_config(raw)
    message = str(excinfo.value)
    assert "timeouts" in message
    for valid_key in ("llm_endpoint_env", "timeout_s", "hard_cutoff_s"):
        assert valid_key in message, f"valid keys not listed: {message}"
