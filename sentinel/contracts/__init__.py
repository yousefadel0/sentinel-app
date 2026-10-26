"""Adapter contracts (P2): DataSource ABC #1 + Actuator ABC #2.

Nothing else in core knows adapter internals (§4).
"""

from sentinel.contracts.actuator import Actuator
from sentinel.contracts.datasource import DataSource

__all__ = ["Actuator", "DataSource"]
