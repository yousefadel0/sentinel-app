"""Correlator package (M2): alerts -> incidents.

Public surface:
    Correlator, Incident, DEFAULT_CORRELATION_WINDOW_S
"""
from sentinel.correlator.correlator import (
    DEFAULT_CORRELATION_WINDOW_S,
    Correlator,
    Incident,
)

__all__ = ["DEFAULT_CORRELATION_WINDOW_S", "Correlator", "Incident"]
