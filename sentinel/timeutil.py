"""Version-independent ISO-8601 parsing.

``datetime.fromisoformat`` only accepts the full range of real-world sensor
timestamps (``...+0000``, trailing ``Z``, 1-9 fractional digits) from Python
3.11; this parser gives identical behavior on every supported version.
"""
from __future__ import annotations

import re
from datetime import datetime, timezone

_RE = re.compile(
    r"^(\d{4}-\d{2}-\d{2})[T ](\d{2}:\d{2}:\d{2})(?:[.,](\d+))?"
    r"(Z|[+-]\d{2}(?::?\d{2})?)?$")


def parse_iso(value: str) -> datetime:
    """Parse to an AWARE datetime (naive input is taken as UTC).

    Raises ValueError on anything that is not an ISO-8601 date-time.
    """
    m = _RE.match(str(value).strip())
    if m is None:
        raise ValueError(f"not an ISO-8601 timestamp: {value!r}")
    day, clock, frac, tz = m.groups()
    micro = ((frac or "0") + "000000")[:6]
    if tz in (None, "Z"):
        off = "+00:00"
    else:
        digits = tz[1:].replace(":", "")
        off = f"{tz[0]}{digits[:2]}:{digits[2:4] or '00'}"
    dt = datetime.fromisoformat(f"{day}T{clock}.{micro}{off}")
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
