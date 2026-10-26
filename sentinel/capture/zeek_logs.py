"""Streaming Zeek TSV log reader (conn/dns/ssl/notice).

Zeek's default ASCII logs carry ``#separator``, ``#fields`` and ``#types``
directive lines. This reader streams line-by-line (never whole-file loads),
resolves the field set from the file's own header, and yields plain dicts
keyed by Zeek field names (``id.orig_h``, ``id.resp_p``, ...).

Malformed rows (wrong column count, unparsable numeric where a directive
declares one) are skipped + counted + logged once each (folded item 2).
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Iterator

from sentinel.logging_setup import get_logger

log = get_logger("sentinel.capture.zeek")

#: Zeek "unset field" marker.
UNSET = "-"


def _coerce(value: str, ztype: str):
    """Convert a Zeek string cell to its declared type ('-'/empty -> None)."""
    if value == UNSET or value == "":
        return None
    if ztype in ("count", "int", "port"):
        try:
            return int(value)
        except ValueError:
            raise ValueError(f"bad {ztype}: {value!r}")
    if ztype in ("double", "interval"):
        try:
            return float(value)
        except ValueError:
            raise ValueError(f"bad {ztype}: {value!r}")
    if ztype == "bool":
        return value.upper() == "T"
    if ztype.startswith("vector") or ztype.startswith("set") or ztype.startswith("table"):
        inner = ztype[ztype.find("[") + 1 : ztype.rfind("]")] if "[" in ztype else "string"
        return [_coerce(cell, inner) for cell in value.split(",")]
    # string / addr / port / enum / time stay as strings here; adapters parse
    return value


def iter_zeek(path: str | Path, *, on_malformed=None) -> Iterator[dict]:
    """Yield one dict per data row from a Zeek ASCII log file.

    Streaming: iterates the open file handle line-by-line. The ``#fields``
    directive defines keys; ``#types`` (when present) drives coercion.
    Malformed rows are skipped and counted via ``on_malformed(count_delta)``
    (surfaced through health()) with one structured warning each — never a
    crash (folded item 2).
    """
    fields: list[str] | None = None
    types: list[str] = []
    malformed = 0
    with open(path, "r", encoding="utf-8") as fh:
        for line_no, line in enumerate(fh, start=1):
            stripped = line.rstrip("\n").rstrip("\t")
            if not stripped:
                continue
            if stripped.startswith("#"):
                directive = stripped.lstrip("#").strip()
                if directive.startswith("separator"):
                    continue  # TSV assumed; tab is the default separator
                if directive.startswith("fields"):
                    fields = directive[len("fields"):].strip().split("\t")
                elif directive.startswith("types"):
                    types = directive[len("types"):].strip().split("\t")
                continue
            if fields is None:
                malformed += 1
                if on_malformed:
                    on_malformed(1)
                log.warning(
                    "zeek_row_before_header_skipped",
                    path=str(path),
                    line_no=line_no,
                )
                continue
            cells = stripped.split("\t")
            if len(cells) != len(fields):
                malformed += 1
                if on_malformed:
                    on_malformed(1)
                log.warning(
                    "zeek_malformed_row_skipped",
                    path=str(path),
                    line_no=line_no,
                    got_columns=len(cells),
                    expected_columns=len(fields),
                )
                continue
            row: dict = {}
            try:
                for name, cell, ztype in zip(fields, cells, types or ["string"] * len(fields)):
                    row[name] = _coerce(cell, ztype)
            except ValueError as exc:
                malformed += 1
                if on_malformed:
                    on_malformed(1)
                log.warning(
                    "zeek_bad_cell_skipped",
                    path=str(path),
                    line_no=line_no,
                    error=str(exc),
                )
                continue
            yield row
    if malformed:
        log.info("zeek_parse_summary", path=str(path), malformed_rows=malformed)


def zeek_to_jsonable(row: MappingLike) -> str:  # type: ignore[name-defined]
    """Stable JSON string of a row — used only for evidence hashing."""
    return json.dumps(row, sort_keys=True, separators=(",", ":"), default=str)


class MappingLike(dict):  # pragma: no cover - typing shim only
    """Typing shim so the annotation above stays honest without mypy stubs."""
