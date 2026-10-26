"""Committed attack generators (M6, D6) — deterministic, offline.

Each module exposes generate(**kwargs) -> list[dict] of eve-shaped
records with harness-private truth keys (see common.py). The ddos
family rides volumetric pcap replay via tools/make_fixtures.py output.
"""
from tools.attackers import brute_force, c2_beacon, dns_tunnel, scan

__all__ = ["brute_force", "c2_beacon", "dns_tunnel", "scan"]
