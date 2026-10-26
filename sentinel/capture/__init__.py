"""Capture layer (M1): parsers, Normalizer, file/replay adapters, health.

First-class per §10-M1: Suricata eve.json streaming parser + Zeek log
ingestion -> Normalizer -> unified Alert (§4), plus per-interface capture
health and honest file/replay dev adapters.
"""
from __future__ import annotations

from sentinel.capture.adapters_file import EveFileDataSource, ZeekLogFileDataSource
from sentinel.capture.eve_parser import iter_eve
from sentinel.capture.health import CaptureHealthTracker, HealthSnapshot
from sentinel.capture.normalizer import (
    ADAPTER_TIERS,
    assign_tier,
    normalize,
)
from sentinel.capture.zeek_logs import iter_zeek

__all__ = [
    "ADAPTER_TIERS",
    "CaptureHealthTracker",
    "EveFileDataSource",
    "HealthSnapshot",
    "ZeekLogFileDataSource",
    "assign_tier",
    "iter_eve",
    "iter_zeek",
    "normalize",
]
