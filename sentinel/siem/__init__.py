"""SIEM dual-role plane (Phase 2 module, P3: never a core dependency).

INBOUND  — identity/auth alerts the wire cannot see (Wazuh alerts.json),
           surfaced as Tier C evidence: alert/human only, never auto-act.
OUTBOUND — Sentinel verdicts exported to the customer SIEM (CEF over
           syslog, or JSON over HTTPS) for compliance.
"""
