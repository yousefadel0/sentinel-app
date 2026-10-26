"""M7 bindcheck — DP1 split: port allowlist (operator policy, fail-closed)
vs loopback-only host invariant (hard security property, NOT overridable).
"""
from __future__ import annotations

import sys
import tempfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sentinel.config.loader import ConfigError  # noqa: E402
from sentinel.ui.bindcheck import validate_bind  # noqa: E402


# -- happy paths -------------------------------------------------------- #
def test_loopback_ipv4_in_allowlist_ok():
    assert validate_bind("127.0.0.1:8080", [8080]) == 8080


def test_any_127_8_address_is_loopback():
    assert validate_bind("127.9.3.7:9090", [8080, 9090]) == 9090


def test_bracketed_ipv6_loopback_ok():
    assert validate_bind("[::1]:8080", [8080]) == 8080


# -- routable rejection: HARD INVARIANT, not operator-overridable -------- #
@pytest.mark.parametrize("bind", ["0.0.0.0:8080", "192.168.1.10:8080",
                                  "[fe80::1]:8080", "::ffff:203.0.113.5:8080"])
def test_routable_bind_rejected_always(bind):
    with pytest.raises(ConfigError, match="loopback"):
        validate_bind(bind, [8080])


def test_routable_rejection_not_overridable_by_config_key():
    """No config value may relax the loopback invariant (DP1 split)."""
    with pytest.raises(ConfigError, match="loopback"):
        validate_bind("0.0.0.0:8080", [8080], allow_routable=True)


# -- port allowlist: operator policy, fail-closed ------------------------ #
def test_port_outside_allowlist_fails_closed_with_offender_named():
    with pytest.raises(ConfigError,
                       match=r"port '8080' not in ops_ui\.allowed_ports"):
        validate_bind("127.0.0.1:8080", [9090])


def test_non_int_entries_rejected():
    with pytest.raises(ConfigError, match="allowed_ports"):
        validate_bind("127.0.0.1:8080", ["8080"])


@pytest.mark.parametrize("bad", [["8080", 1.5], [None], [[]]])
def test_mixed_or_wrong_type_entries_rejected(bad):
    with pytest.raises(ConfigError, match="allowed_ports"):
        validate_bind("127.0.0.1:8080", bad)


def test_missing_allowed_ports_is_operator_policy_error():
    with pytest.raises(ConfigError, match="allowed_ports"):
        validate_bind("127.0.0.1:8080", None)


# -- malformed bind strings ---------------------------------------------- #
@pytest.mark.parametrize("bind", ["localhost:8080", "127.0.0.1",
                                  "127.0.0.1:notaport", "[::1]8080"])
def test_malformed_bind_clear_error(bind):
    with pytest.raises(ConfigError, match="ops_ui.bind"):
        validate_bind(bind, [8080])


def test_port_out_of_range():
    with pytest.raises(ConfigError, match="1024"):
        validate_bind("127.0.0.1:80", [80])
    with pytest.raises(ConfigError, match="65535"):
        validate_bind("127.0.0.1:70000", [70000])


# -- boot wiring: loader validates whole config even when disabled -------- #
def _cfg_yaml(ops_ui_block: str) -> Path:
    """Valid fixture minus its ops_ui block, plus the given fresh block."""
    import yaml
    raw = yaml.safe_load(
        (Path(__file__).parent / "fixtures" / "valid_config.yaml").read_text())
    raw.pop("ops_ui", None)
    raw["ops_ui"] = yaml.safe_load(ops_ui_block)
    tmp = Path(tempfile.mkdtemp()) / "c.yaml"
    tmp.write_text(yaml.safe_dump(raw))
    return tmp


def test_loader_refuses_routable_bind_even_when_disabled(tmp_path):
    cfg = _cfg_yaml(
        'enabled: false\n'
        'bind: "0.0.0.0:8080"\n'
        'auth_token_env: SENTINEL_OPS_UI_TOKEN\n'
        'allowed_ports: [8080]\n')
    from sentinel.config.loader import load_config
    with pytest.raises(ConfigError, match="loopback"):
        load_config(cfg)


def test_loader_aggregates_bind_error_with_other_violations(tmp_path):
    """Fail-closed aggregation: bind error appears alongside other errors."""
    cfg = _cfg_yaml(
        'enabled: true\n'
        'bind: "192.168.1.5:8080"\n'
        'auth_token_env: SENTINEL_OPS_UI_TOKEN\n'
        'allowed_ports: [8080]\n')
    body = cfg.read_text().replace("autonomy_level: 0",
                                   "autonomy_level: 9")
    cfg.write_text(body)
    from sentinel.config.loader import load_config
    with pytest.raises(ConfigError) as ei:
        load_config(cfg)
    msg = str(ei.value)
    assert "loopback" in msg and "autonomy_level" in msg


def test_valid_fixture_still_loads(valid_config_path):
    from sentinel.config.loader import load_config
    raw = load_config(valid_config_path)
    assert raw["ops_ui"]["allowed_ports"] == [8080, 8081]
