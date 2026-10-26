"""Derived DNS features — computed at the source so no query text ever
leaves the adapter (the Alert model carries only derived signal tokens)."""
from __future__ import annotations

import math
from collections import Counter

#: Signal token a source attaches to a DNS event whose QNAME looks tunnel-ish.
SUSPICIOUS_DNS = "dns_suspicious_name"

_MIN_LEN = 50          # total qname length (typical names are far shorter)
_MIN_LABEL = 28        # a single very long label (encoded payload chunk)
_ENTROPY = 3.6         # bits/char of the longest label (random-looking)


def _entropy(text: str) -> float:
    if not text:
        return 0.0
    n = len(text)
    return -sum(c / n * math.log2(c / n) for c in Counter(text).values())


def dns_signals(qname: str | None) -> tuple[str, ...]:
    """() for benign-looking names, (SUSPICIOUS_DNS,) for tunnel-like ones."""
    if not qname:
        return ()
    name = qname.strip(".").lower()
    labels = name.split(".")
    longest = max(labels, key=len)
    long_name = len(name) >= _MIN_LEN
    long_label = len(longest) >= _MIN_LABEL
    # Encoded payload chunks (base32/hex/base64) are unhyphenated; long
    # hyphenated service names are human-chosen words, not data.
    random_label = (len(longest) >= 16 and "-" not in longest
                    and _entropy(longest) >= _ENTROPY)
    if random_label and (long_name or long_label):
        return (SUSPICIOUS_DNS,)
    return ()
