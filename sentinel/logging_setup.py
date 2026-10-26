"""structlog-style JSON logging (§8 tech stack).

Every log line is a single JSON object on stderr — machine-parseable,
audit-friendly. Supports structlog-style calls: log.info("event", key=value).
"""
from __future__ import annotations

import json
import logging
import sys
from datetime import datetime, timezone
from typing import Any

_RESERVED = set(logging.LogRecord("", 0, "", 0, "", (), "").__dict__) | {
    "message", "asctime",
}


class JsonFormatter(logging.Formatter):
    """Render LogRecords as one-line JSON objects."""

    def format(self, record: logging.LogRecord) -> str:
        entry: dict[str, Any] = {
            "ts": datetime.fromtimestamp(record.created, tz=timezone.utc)
                  .isoformat(timespec="milliseconds"),
            "level": record.levelname.lower(),
            "logger": record.name,
            "event": record.getMessage(),
        }
        for key, value in record.__dict__.items():
            if key not in _RESERVED and not key.startswith("_"):
                try:
                    json.dumps(value)
                    entry[key] = value
                except (TypeError, ValueError):
                    entry[key] = repr(value)
        if record.exc_info:
            entry["exc"] = self.formatException(record.exc_info)
        return json.dumps(entry, separators=(",", ":"), ensure_ascii=False)


class JsonLogger:
    """structlog-style facade over stdlib logging.

    Usage: log.info("boot_check_passed", path=p, dry_run=True).
    Keyword args merge into the record's `extra` so JsonFormatter emits them
    as top-level JSON fields.
    """

    def __init__(self, name: str) -> None:
        self._logger = logging.getLogger(name)

    def _log(self, level: int, event: str, **fields: Any) -> None:
        if self._logger.isEnabledFor(level):
            self._logger.log(level, event, extra=dict(fields))

    def debug(self, event: str, **fields: Any) -> None:
        self._log(logging.DEBUG, event, **fields)

    def info(self, event: str, **fields: Any) -> None:
        self._log(logging.INFO, event, **fields)

    def warning(self, event: str, **fields: Any) -> None:
        self._log(logging.WARNING, event, **fields)

    def error(self, event: str, **fields: Any) -> None:
        self._log(logging.ERROR, event, **fields)


def setup_logging(level: str = "INFO") -> None:
    """Configure root logging to emit structlog-style JSON lines (stderr)."""
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(JsonFormatter())
    root = logging.getLogger()
    root.handlers[:] = [handler]
    root.setLevel(getattr(logging, level.upper(), logging.INFO))


def get_logger(name: str) -> JsonLogger:
    """Logger bound into the JSON pipeline; usage: log.info("msg", key=value)."""
    return JsonLogger(name)
