"""Incremental log tailing for LIVE capture (Phase 1).

``TailReader`` returns only the complete lines appended to a file since the
last call. It is restart-safe (offsets persist in a small JSON state file)
and rotation-safe (inode change or truncation restarts at offset 0).

Guarantees:
* a trailing partial line (writer mid-flush) is held back until its newline
  arrives — never parsed half-written;
* a missing file yields nothing and is reported via ``exists`` (P4: the
  capture loop never crashes on a sensor that is not up yet);
* O(new bytes) memory per poll, bounded by ``max_bytes_per_poll``.
"""
from __future__ import annotations

import json
import os
from pathlib import Path

from sentinel.logging_setup import get_logger

log = get_logger("sentinel.capture.tail")

DEFAULT_MAX_BYTES_PER_POLL = 8 * 1024 * 1024


class OffsetStore:
    """Tiny JSON-file persistence for per-source tail state."""

    def __init__(self, path: str | Path | None) -> None:
        self._path = Path(path) if path else None
        self._data: dict[str, dict] = {}
        if self._path and self._path.exists():
            try:
                loaded = json.loads(self._path.read_text(encoding="utf-8"))
                if isinstance(loaded, dict):
                    self._data = loaded
            except (OSError, ValueError):
                log.warning("offset_state_unreadable", path=str(self._path))

    def get(self, key: str) -> dict:
        return dict(self._data.get(key, {}))

    def put(self, key: str, state: dict) -> None:
        self._data[key] = state
        if self._path is None:
            return
        try:
            self._path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self._path.with_suffix(self._path.suffix + ".tmp")
            tmp.write_text(json.dumps(self._data, sort_keys=True),
                           encoding="utf-8")
            os.replace(tmp, self._path)
        except OSError:
            log.warning("offset_state_write_failed", path=str(self._path))


class TailReader:
    """Yield newly appended complete lines of one file."""

    def __init__(self, path: str | Path, *, state: OffsetStore | None = None,
                 start_at_end: bool = False,
                 max_bytes_per_poll: int = DEFAULT_MAX_BYTES_PER_POLL) -> None:
        self._path = Path(path)
        self._store = state or OffsetStore(None)
        self._key = str(self._path.resolve())
        self._max = max_bytes_per_poll
        saved = self._store.get(self._key)
        self._offset: int = int(saved.get("offset", 0))
        self._inode = saved.get("inode")
        self._line_no: int = int(saved.get("line_no", 0))
        self._rotations: int = 0
        self.exists: bool = False
        # First ever run on a pre-existing file: optionally skip history.
        self._skip_history = start_at_end and not saved

    @property
    def line_no(self) -> int:
        """Monotonic count of lines returned so far (survives rotation)."""
        return self._line_no

    @property
    def rotations(self) -> int:
        return self._rotations

    def _persist(self) -> None:
        self._store.put(self._key, {"offset": self._offset,
                                    "inode": self._inode,
                                    "line_no": self._line_no})

    def read_new_lines(self) -> list[str]:
        try:
            st = self._path.stat()
        except OSError:
            self.exists = False
            return []
        self.exists = True
        inode = getattr(st, "st_ino", None) or None

        if self._skip_history:
            self._offset, self._inode = st.st_size, inode
            self._skip_history = False
            self._persist()
            return []

        rotated = (self._inode is not None and inode is not None
                   and inode != self._inode)
        if rotated or st.st_size < self._offset:
            log.info("tail_rotation_detected", path=str(self._path),
                     rotated=rotated, size=st.st_size, offset=self._offset)
            self._rotations += 1
            self._offset = 0
        self._inode = inode

        if st.st_size == self._offset:
            return []
        try:
            with open(self._path, "rb") as fh:
                fh.seek(self._offset)
                chunk = fh.read(self._max)
        except OSError:
            self.exists = False
            return []

        end = chunk.rfind(b"\n")
        if end < 0:
            return []                      # only a partial line so far
        complete = chunk[: end + 1]
        self._offset += len(complete)
        lines = complete.decode("utf-8", errors="replace").splitlines()
        self._line_no += len(lines)
        self._persist()
        return lines
