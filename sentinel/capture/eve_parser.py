"""Streaming eve.json parser (Suricata).

STREAMING by doctrine (§10-M1): reads line-by-line via a file iterator —
never loads whole files into memory. Malformed lines are skipped, counted
and logged once each (folded item 2); the capture loop never crashes on
bad input.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Iterator

from sentinel.logging_setup import get_logger

log = get_logger("sentinel.capture.eve")


def iter_eve(path: str | Path, *, on_malformed=None) -> Iterator[dict]:
    """Yield parsed eve.json records one at a time from *path*.

    * O(1) memory: opens the file and iterates lines; no read() of the blob.
    * Malformed JSON lines: skipped, counted via ``on_malformed(count_delta)``
      (surfaced through health()), one structured warning log per occurrence.
    * Empty file / no valid lines: yields nothing — never raises for content
      issues (P4 degrades gracefully).
    """
    malformed = 0
    with open(path, "r", encoding="utf-8") as fh:
        for line_no, line in enumerate(fh, start=1):
            stripped = line.strip()
            if not stripped:
                continue
            try:
                record = json.loads(stripped)
            except json.JSONDecodeError as exc:
                malformed += 1
                if on_malformed:
                    on_malformed(1)
                log.warning(
                    "eve_malformed_line_skipped",
                    path=str(path),
                    line_no=line_no,
                    error=str(exc),
                )
                continue
            if not isinstance(record, dict):
                malformed += 1
                if on_malformed:
                    on_malformed(1)
                log.warning(
                    "eve_non_object_line_skipped",
                    path=str(path),
                    line_no=line_no,
                    got_type=type(record).__name__,
                )
                continue
            yield record
    if malformed:
        log.info("eve_parse_summary", path=str(path), malformed_lines=malformed)
