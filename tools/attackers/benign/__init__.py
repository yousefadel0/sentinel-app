"""Benign traffic generators (Q2) — deterministic, no attack signals.

FP-rate becomes measurable by construction: these produce purely-benign
events; any incident they form that gets a non-notify outcome counts as
a false positive per D4.
"""
from tools.attackers.benign import http_browse, periodic_dns, ssh_session

__all__ = ["http_browse", "periodic_dns", "ssh_session"]
