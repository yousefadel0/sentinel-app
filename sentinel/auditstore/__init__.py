"""Sentinel append-only audit store (M6) — public surface.

SQLite-backed, INSERT-only at the application layer (D5). Persists
decisions, G7 verbatim LLM pairs, gated actions, rollbacks and KPI
events; every row carries an ISO timestamp + case_id correlation key.
"""
from sentinel.auditstore.store import SCHEMA_VERSION, Store

__all__ = ["SCHEMA_VERSION", "Store"]
