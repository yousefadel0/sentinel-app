"""Strict fail-closed config loader/validator for Sentinel.

Policy (operator decision, P5 safety over convenience):
  * unknown key at ANY level      -> refuse boot
  * missing required key          -> refuse boot
  * wrong type / bad enum / out-of-bounds -> refuse boot
Every error names the offending key, lists the valid keys, and cites "(ref §8)".
"""
from __future__ import annotations

import ipaddress
from pathlib import Path
from typing import Any

import yaml

from sentinel.config.schema import (
    CROSS_FIELD_RULES,
    SCHEMA,
    TOP_LEVEL_KEYS,
)

REF = "(ref §8)"


class ConfigError(Exception):
    """Raised when config.yaml fails strict validation. Refuses boot."""


def is_ipv4(value: str) -> bool:
    """True iff value parses as a dotted-quad IPv4 address."""
    try:
        ipaddress.IPv4Address(value)
        return True
    except ValueError:
        return False


def _valid_keys(shape: dict) -> str:
    return ", ".join(sorted(shape))


def _type_name(t: Any) -> str:
    if isinstance(t, tuple):
        return "|".join(x.__name__ for x in t)
    return t.__name__


def _check_scalar(path: str, value: Any, spec: dict, errors: list[str]) -> None:
    cons = spec.get("constraints") or {}
    types = spec["type"] if isinstance(spec["type"], tuple) else (spec["type"],)

    # bool is an int subclass — reject it where ints are expected
    if isinstance(value, bool) and bool not in types:
        errors.append(f"{path}: expected type {_type_name(types)}, got bool {value!r} {REF}")
        return
    if not isinstance(value, types):
        errors.append(
            f"{path}: expected type {_type_name(types)}, "
            f"got {type(value).__name__} {value!r} {REF}"
        )
        return

    if "enum" in cons and value not in cons["enum"]:
        errors.append(
            f"{path}: invalid value {value!r}; valid values: "
            f"{', '.join(map(str, cons['enum']))} {REF}"
        )
    if "min" in cons and value < cons["min"]:
        errors.append(f"{path}: value {value!r} below minimum {cons['min']} {REF}")
    if "max" in cons and value > cons["max"]:
        errors.append(f"{path}: value {value!r} above maximum {cons['max']} {REF}")
    if cons.get("ipv4") and not is_ipv4(value):
        errors.append(f"{path}: {value!r} is not a valid IPv4 address {REF}")


def _validate_dict(path: str, data: Any, shape: dict, errors: list[str]) -> None:
    """Validate a mapping node against `shape` (key -> field spec)."""
    if not isinstance(data, dict):
        errors.append(f"{path}: expected type dict, got {type(data).__name__} {REF}")
        return

    unknown = sorted(set(data) - set(shape))
    if unknown:
        errors.append(
            f"{path}: unknown key(s) {', '.join(unknown)}; "
            f"valid keys: {_valid_keys(shape)} {REF}"
        )

    for key, sub in shape.items():
        kpath = f"{path}.{key}"
        present = key in data
        if present and data[key] is None and sub["required"]:
            errors.append(
                f"{kpath}: required key missing (got null); valid keys: "
                f"{_valid_keys(shape)} {REF}"
            )
        elif not present and sub["required"]:
            errors.append(
                f"{kpath}: required key missing; valid keys: "
                f"{_valid_keys(shape)} {REF}"
            )
        elif present and data[key] is not None:
            _validate_node(kpath, data[key], sub, errors)

    # conditional requirements — independent of plain `required`:
    # e.g. actuators[].url required iff actuators[].type == webhook_soar
    for key, sub in shape.items():
        cond_req = (sub.get("constraints") or {}).get("cond_req")
        if cond_req and data.get(cond_req[0]) == cond_req[1] \
                and data.get(key) in (None, ""):
            errors.append(
                f"{path}.{key}: required when '{cond_req[0]}' == '{cond_req[1]}'; "
                f"valid keys: {_valid_keys(shape)} {REF}"
            )


def _validate_list(path: str, data: Any, spec: dict, errors: list[str]) -> None:
    cons = spec.get("constraints") or {}
    if not isinstance(data, list):
        errors.append(f"{path}: expected type list, got {type(data).__name__} {REF}")
        return
    if "min_len" in cons and len(data) < cons["min_len"]:
        errors.append(
            f"{path}: must contain at least {cons['min_len']} item(s); "
            f"got {len(data)} {REF}"
        )
        return
    item_type = cons.get("item_type")
    item_keys = cons.get("item_keys")
    for i, item in enumerate(data):
        ipath = f"{path}[{i}]"
        if item_keys is not None:
            _validate_node(ipath, item,
                           {"type": dict, "required": True,
                            "constraints": {"item_keys": item_keys}}, errors)
        elif item_type is not None and not isinstance(item, item_type):
            errors.append(
                f"{ipath}: expected item type {item_type.__name__}, "
                f"got {type(item).__name__} {item!r} {REF}"
            )
        elif item_type is not None and cons.get("item_constraints"):
            _check_scalar(ipath, item, {"type": item_type,
                                       "constraints": cons["item_constraints"]}, errors)


def _validate_node(path: str, data: Any, spec: dict, errors: list[str]) -> None:
    """Dispatch on declared node type: dict | list | scalar leaf."""
    node_type = spec["type"]
    cons = spec.get("constraints") or {}

    if node_type is dict:
        shape = spec.get("keys") or cons.get("item_keys") or {}
        _validate_dict(path, data, shape, errors)
    elif node_type is list:
        _validate_list(path, data, spec, errors)
    else:
        _check_scalar(path, data, spec, errors)


def validate_config(raw: dict) -> dict:
    """Validate a raw mapping against the §8 schema. Returns it unchanged.

    Raises ConfigError listing ALL violations found (fail-closed).
    """
    if not isinstance(raw, dict):
        raise ConfigError(f"config: expected a YAML mapping at top level, "
                          f"got {type(raw).__name__} {REF}")

    errors: list[str] = []

    unknown = sorted(set(raw) - set(TOP_LEVEL_KEYS))
    if unknown:
        errors.append(
            f"config: unknown top-level key(s) {', '.join(unknown)}; "
            f"valid keys: {', '.join(TOP_LEVEL_KEYS)} {REF}"
        )

    for key in TOP_LEVEL_KEYS:
        spec = SCHEMA[key]
        if key not in raw and spec["required"]:
            errors.append(
                f"config.{key}: required section missing; valid keys: "
                f"{', '.join(TOP_LEVEL_KEYS)} {REF}"
            )
        elif key in raw:
            _validate_node(f"config.{key}", raw[key], spec, errors)

    for left, op, right, why in CROSS_FIELD_RULES:
        lv, rv = _dig(raw, left), _dig(raw, right)
        if lv is None or rv is None:
            continue  # absence already reported above
        ok = {"<=": lambda a, b: a <= b, ">=": lambda a, b: a >= b}[op](lv, rv)
        if not ok:
            errors.append(f"config: cross-field violation — {left}={lv!r} must be "
                          f"{op} {right}={rv!r} ({why}) {REF}")

    # M7 (§10-M7): the M0-deferred ops_ui.bind check lands at boot here.
    # Runs even when enabled:false — §8 configs are validated whole; a
    # config that COULD not be served safely is refused, not deferred.
    # Port allowlist = operator policy; loopback-only host = hard
    # invariant enforced inside bindcheck (not overridable via config).
    ops_ui = raw.get("ops_ui")
    if isinstance(ops_ui, dict):
        try:
            from sentinel.ui.bindcheck import validate_bind
            validate_bind(ops_ui.get("bind"), ops_ui.get("allowed_ports"))
        except ConfigError as exc:
            errors.append(str(exc))
        except ImportError:  # pragma: no cover - extra absent in base install
            pass  # schema-level shape checks above still ran

    if errors:
        raise ConfigError("\n".join(errors))
    return raw


def _dig(raw: dict, dotted: str) -> Any:
    node: Any = raw
    for part in dotted.split("."):
        if not isinstance(node, dict) or part not in node:
            return None
        node = node[part]
    return node


def load_config(path: str | Path) -> dict:
    """Load and strictly validate config.yaml. Raises ConfigError on any fault."""
    p = Path(path)
    if not p.is_file():
        raise ConfigError(f"config file not found: {p} {REF}")
    try:
        raw = yaml.safe_load(p.read_text(encoding="utf-8"))
    except yaml.YAMLError as exc:
        raise ConfigError(f"config: invalid YAML syntax in {p}: {exc} {REF}") from exc
    if isinstance(raw, dict):
        overlay = ui_override_path(raw)
        if overlay is not None and overlay.is_file():
            try:
                changes = yaml.safe_load(overlay.read_text(encoding="utf-8"))
            except yaml.YAMLError as exc:
                raise ConfigError(f"invalid UI settings file {overlay}: {exc}") from exc
            if not isinstance(changes, dict) or set(changes) - {
                    "site", "policy", "limits", "notifiers", "enforcement_dry_run"}:
                raise ConfigError("invalid UI settings keys")
            for key, value in changes.items():
                if key == "site":
                    if not isinstance(value, dict) or set(value) != {"protected_ips"}:
                        raise ConfigError("UI settings may change only site.protected_ips")
                    raw[key] = {**raw.get(key, {}), **value}
                elif key in ("policy", "limits"):
                    if not isinstance(value, dict):
                        raise ConfigError(f"invalid UI settings {key}")
                    raw[key] = {**raw.get(key, {}), **value}
                else:
                    raw[key] = value
    return validate_config(raw)


def ui_override_path(raw: dict) -> Path | None:
    """UI settings live beside the durable audit store, including in Docker."""
    path = (raw.get("audit_store") or {}).get("path")
    return Path(path).with_name("ui-settings.yaml") if isinstance(path, str) and path else None
