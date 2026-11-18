"""Declarative §8 config schema shape for Sentinel.

Single source of truth for what a valid config.yaml contains. The loader
(`sentinel.config.loader`) walks this table and enforces STRICT fail-closed
validation: unknown keys AND missing required keys at any level refuse boot
with an error naming the offending key, the valid keys, and "(ref §8)".

Field spec tuples: (type, required, constraints)
  type        : python type or tuple of allowed types
  required    : bool
  constraints : optional dict with:
                  enum      -> set/list of allowed values
                  min/max   -> numeric bounds (inclusive)
                  item_type -> element type for lists
                  ipv4      -> True: validate dotted-quad IPv4 format
                  cond_req  -> (key, value): required iff sibling key == value
"""
from __future__ import annotations

TOP_LEVEL_KEYS = (
    "site",
    "capture_interfaces",
    "placement",
    "monitored_vlans",
    "unmapped_vlans",
    "has_nat",
    "brain",
    "actuators",
    "autonomy_level",
    "enforcement_dry_run",
    "limits",
    "ops_ui",  # M7 module block; validated here since it is part of §8 schema
    "audit_store",  # M6 (D5): optional SQLite append-only audit store path
    "policy",  # P1: optional decision thresholds
    "critical_response",  # P2: urgent escalation with a deadline
    "notifiers",  # Phase 5: optional outbound notification channels
    "siem",  # M8 (PHASE-2): optional SIEM dual-role plane connector block
)

SCHEMA: dict[str, dict] = {
    "enforcement_dry_run": {"type": bool, "required": False},
    "site": {
        "type": dict,
        "required": True,
        "keys": {
            "name": {"type": str, "required": True},
            "critical_assets": {
                "type": list,
                "required": True,
                "constraints": {
                    "item_keys": {
                        "ip": {"type": str, "required": True,
                               "constraints": {"ipv4": True}},
                        "hostname": {"type": str, "required": True},
                        # default "critical"; G1 allowlist members
                        "criticality": {"type": str, "required": False,
                                        "constraints": {"enum": (
                                            "critical", "high", "medium", "low")}},
                    }
                },
            },
            "protected_ips": {"type": list, "required": False,
                              "constraints": {"item_type": str,
                                              "item_constraints": {"ipv4": True}}},
            # Important assets that are NOT G1-protected (weights the score only).
            "assets": {
                "type": list,
                "required": False,
                "constraints": {
                    "item_keys": {
                        "ip": {"type": str, "required": True,
                               "constraints": {"ipv4": True}},
                        "hostname": {"type": str, "required": True},
                        "criticality": {"type": str, "required": True,
                                        "constraints": {"enum": (
                                            "critical", "high", "medium", "low")}},
                    }
                },
            },
        },
    },
    "capture_interfaces": {
        "type": list,
        "required": True,
        "constraints": {"min_len": 1,
                        "item_keys": {
                            "name": {"type": str, "required": True},
                            "type": {"type": str, "required": True,
                                     "constraints": {"enum": ("af_packet",)}},
                            "iface": {"type": str, "required": True},
                        }},
    },
    "placement": {
        "type": dict,
        "required": True,
        "keys": {
            "primary_tap": {"type": str, "required": True},
            "secondary_tap": {"type": str, "required": True},
            "asymmetric_risk": {"type": str, "required": True,
                                "constraints": {"enum": ("high", "medium", "low")}},
        },
    },
    "monitored_vlans": {
        "type": list, "required": True,
        "constraints": {"min_len": 1, "item_type": str},
    },
    "unmapped_vlans": {
        "type": list, "required": True,
        "constraints": {"item_type": str},
    },
    "has_nat": {"type": bool, "required": True},
    "brain": {
        "type": dict,
        "required": True,
        "keys": {
            "llm_endpoint_env": {"type": str, "required": True},
            "timeout_s": {"type": int, "required": True,
                          "constraints": {"min": 1}},
            "hard_cutoff_s": {"type": int, "required": True,
                              "constraints": {"min": 1}},
            # Own model: raw (default) or OpenAI-compatible chat completions.
            "api_style": {"type": str, "required": False,
                          "constraints": {"enum": ("raw", "openai")}},
            "model": {"type": str, "required": False,
                      "constraints": {"cond_req": ("api_style", "openai"),
                                      "min_len": 1}},
            "api_key_env": {"type": str, "required": False,
                            "constraints": {"min_len": 1}},
        },
    },
    "actuators": {
        "type": list,
        "required": True,
        "constraints": {"min_len": 1,
                        "item_keys": {
                            "type": {"type": str, "required": True,
                                     "constraints": {"enum": ("nftables_local",
                                                              "webhook_soar")}},
                            # plain string for M0; port-range validation is
                            # deferred to M7 per operator decision.
                            # https-scheme check belongs to M4/M5 actuator work.
                            "url": {"type": str, "required": False,
                                    "constraints": {"cond_req": ("type", "webhook_soar")}},
                        }},
    },
    "autonomy_level": {
        # REQUIRED-EXPLICIT (operator decision): §6's "default 0" describes the
        # philosophy (ALWAYS start shadow), not permission to omit the key.
        "type": int, "required": True,
        "constraints": {"min": 0, "max": 3},
    },
    "limits": {
        "type": dict,
        "required": True,
        "keys": {
            "max_blocks_per_min": {"type": int, "required": True,
                                   "constraints": {"min": 1}},
            "max_blocks_per_hour": {"type": int, "required": True,
                                    "constraints": {"min": 1}},
            "default_ttl_min": {"type": int, "required": True,
                                "constraints": {"min": 1, "max": 60}},  # G3: TTL ≤ 60
        },
    },
    "ops_ui": {
        # M7 (§10-M7): Minimal Ops UI — optional block; `enabled` default is
        # FALSE via the DEFAULTS table (never on by default). `bind` was a
        # plain string for M0; the deferred check lands in M7 as boot-time
        # validation in sentinel.ui.bindcheck (port allowlist = operator
        # policy; loopback-only host = hard invariant, not overridable).
        "type": dict,
        "required": False,
        "keys": {
            "enabled": {"type": bool, "required": True},
            "bind": {"type": str, "required": True},   # "host:port", see bindcheck
            "auth_token_env": {"type": str, "required": True},
            "allowed_ports": {"type": list, "required": True,
                              "constraints": {"item_type": int}},
            # "token" (legacy shared header token) or "accounts" (named
            # users, roles viewer/analyst/admin, MFA, sessions).
            "auth_mode": {"type": str, "required": False,
                          "constraints": {"enum": ("token", "accounts")}},
            "accounts_db": {"type": str, "required": False,
                            "constraints": {"min_len": 1}},
            # accounts mode only: also accept the header token (automation).
            # Off by default: a shared token bypasses MFA and names no one.
            "allow_token_api": {"type": bool, "required": False},
        },
    },
    "audit_store": {
        # M6 (D5): optional block — when present, `path` is required and
        # names the SQLite append-only audit store file.
        "type": dict,
        "required": False,
        "keys": {
            "path": {"type": str, "required": True,
                     "constraints": {"min_len": 1}},
        },
    },
    "policy": {
        # P1: decision thresholds. >= auto_act_threshold may act alone;
        # between human_approval_threshold and it needs a human; below: log.
        "type": dict,
        "required": False,
        "keys": {
            "auto_act_threshold": {"type": (int, float), "required": False,
                                   "constraints": {"min": 0.5, "max": 1.0}},
            "human_approval_threshold": {"type": (int, float), "required": False,
                                         "constraints": {"min": 0.1, "max": 1.0}},
            "report_threshold": {"type": (int, float), "required": False,
                                  "constraints": {"min": 0.1, "max": 1.0}},
            "approval_timeout_minutes": {"type": int, "required": False,
                                         "constraints": {"min": 1, "max": 60}},
            "report_timeout_minutes": {"type": int, "required": False,
                                       "constraints": {"min": 1, "max": 120}},
            "report_fallback_actions": {
                "type": list, "required": False,
                "constraints": {"min_len": 1, "item_type": str,
                                "item_constraints": {"enum": (
                                    "throttle_src", "block_ip_temp")}}},
            # Risk floor: an incident whose risk score (confidence x asset
            # weight x severity) is below this is logged, never escalated.
            "min_risk_score": {"type": (int, float), "required": False,
                               "constraints": {"min": 0.0, "max": 0.9}},
            # Noise control: Suricata rule IDs that never open an incident.
            "suppress_signature_ids": {
                "type": list, "required": False,
                "constraints": {"item_type": int}},
            "suppress_engine_events": {"type": bool, "required": False},
        },
    },
    "critical_response": {
        "type": dict,
        "required": False,
        "keys": {
            "enabled": {"type": bool, "required": True},
            "min_score": {"type": (int, float), "required": False,
                          "constraints": {"min": 0.5, "max": 1.0}},
            "deadline_minutes": {"type": int, "required": False,
                                 "constraints": {"min": 5, "max": 60}},
            "auto_remediate_on_timeout": {"type": bool, "required": False},
            "reminder_minutes": {"type": int, "required": False,
                                 "constraints": {"min": 1, "max": 30}},
        },
    },
    "notifiers": {
        # Phase 5: optional channels. Secrets (webhook URL / bot token) are
        # never in the file — `url_env` names the environment variable.
        "type": list,
        "required": False,
        "constraints": {"item_keys": {
            "type": {"type": str, "required": True,
                     "constraints": {"enum": ("webhook", "telegram")}},
            "url_env": {"type": str, "required": True,
                        "constraints": {"min_len": 1}},
            "format": {"type": str, "required": False,
                       "constraints": {"enum": ("slack", "teams", "generic")}},
            "chat_id": {"type": str, "required": False,
                        "constraints": {"cond_req": ("type", "telegram")}},
            "approvals": {"type": bool, "required": False},
            # Only these Telegram user ids may approve/deny (recommended).
            "allowed_user_ids": {"type": list, "required": False,
                                 "constraints": {"item_type": str}},
            # Send a daily summary at this hour (UTC, 0-23).
            "daily_summary_hour_utc": {"type": int, "required": False,
                                       "constraints": {"min": 0, "max": 23}},
        }},
    },
    "siem": {
        # M8 (PHASE-2): optional SIEM dual-role plane connector. Absent
        # block ⇒ fully inert; present-but-disabled ⇒ validated whole but
        # equally inert (ops_ui semantics). P3 holds: no decision ever
        # depends on SIEM presence. Sub-switches are independent; module
        # DEFAULTS for poll intervals / batch size apply at read sites in
        # sentinel.siem (schema keeps them explicit-required).
        "type": dict,
        "required": False,
        "keys": {
            "enabled": {"type": bool, "required": True},
            "inbound": {
                "type": dict, "required": True,
                "keys": {
                    "enabled": {"type": bool, "required": True},
                    "source": {"type": str, "required": True,
                               "constraints": {"enum": ("wazuh",)}},
                    "api_url": {"type": str, "required": False,
                                "constraints": {"cond_req": ("enabled", True),
                                                "min_len": 1}},
                    "poll_interval_seconds": {"type": int, "required": True,
                                              "constraints": {"min": 1}},
                    "token_env": {"type": str, "required": False,
                                  "constraints": {"cond_req": ("enabled", True),
                                                  "min_len": 1}},
                    # Phase 5: Wazuh alerts.json path (file-tail ingestion;
                    # no SIEM credentials needed by Sentinel).
                    "alerts_file": {"type": str, "required": False},
                },
            },
            "outbound": {
                "type": dict, "required": True,
                "keys": {
                    "enabled": {"type": bool, "required": True},
                    "endpoint": {"type": str, "required": False,
                                 "constraints": {"cond_req": ("enabled", True),
                                                 "min_len": 1}},
                    "batch_size": {"type": int, "required": True,
                                   "constraints": {"min": 1, "max": 1000}},
                    "poll_interval_seconds": {"type": int, "required": True,
                                              "constraints": {"min": 1}},
                    "token_env": {"type": str, "required": False,
                                  "constraints": {"cond_req": ("enabled", True),
                                                  "min_len": 1}},
                },
            },
        },
    },
}

CROSS_FIELD_RULES = (
    ("policy.report_threshold", "<=", "policy.human_approval_threshold",
     "report threshold must not exceed the approval threshold"),
    ("policy.human_approval_threshold", "<=", "policy.auto_act_threshold",
     "approval threshold must not exceed the auto-act threshold"),
    ("brain.hard_cutoff_s", "<=", "brain.timeout_s",
     "hard cutoff must be <= timeout"),
    ("limits.max_blocks_per_hour", ">=", "limits.max_blocks_per_min",
     "per-hour limit must be >= per-minute limit"),
)
