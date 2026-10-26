"""Verdict export: decisions table -> customer SIEM.

Endpoint schemes:
  syslog+udp://host:514 | syslog+tcp://host:514   CEF line per decision
  https://host/path                                JSON batch + Bearer token
                                                   (token from ``token_env``)

Delivery is at-least-once with a persisted high-water mark: the last
exported ``decisions.id`` is stored in a small state file, advanced only
after a successful send, so a SIEM outage delays export but never loses a
verdict. Reads are SELECT-only against the audit store (it stays append-only).
"""
from __future__ import annotations

import json
import os
import socket
import urllib.request
from pathlib import Path
from urllib.parse import urlparse

from sentinel.auditstore.store import Store
from sentinel.logging_setup import get_logger

log = get_logger("sentinel.siem.outbound")

_SEV = {"auto_act": 9, "auto_throttle": 8, "human_approval": 7,
        "escalate_human": 7, "notify_only": 4, "log_only": 2}


def _cef_escape(value: object, *, header: bool = False) -> str:
    text = str(value if value is not None else "")
    text = text.replace("\\", "\\\\")
    text = text.replace("|" if header else "=", "\\|" if header else "\\=")
    return text.replace("\r", " ").replace("\n", " ")


def to_cef(row: dict) -> str:
    """One decision row as an ArcSight CEF:0 line (injection-safe)."""
    outcome = row["outcome"]
    ext = " ".join(f"{k}={_cef_escape(v)}" for k, v in (
        ("externalId", row["incident_id"]), ("outcome", outcome),
        ("cs1Label", "tier"), ("cs1", row["tier"]),
        ("cn1Label", "score"), ("cn1", f"{float(row['score']):.4f}"),
        ("msg", row["would"]), ("rt", row["ts"]),
        ("cs2Label", "caseId"), ("cs2", row["case_id"])))
    return (f"CEF:0|Sentinel|Sentinel|1|{_cef_escape(outcome, header=True)}|"
            f"Sentinel verdict: {_cef_escape(outcome, header=True)}|"
            f"{_SEV.get(outcome, 3)}|{ext}")


class SiemExporter:
    def __init__(self, store: Store, endpoint: str, state_path: str | Path, *,
                 token_env: str | None = None, batch_size: int = 100,
                 sender=None) -> None:
        self._store, self._ep = store, endpoint
        self._state = Path(state_path)
        self._token_env, self._batch = token_env, batch_size
        self._u = urlparse(endpoint)
        if self._u.scheme not in ("syslog+udp", "syslog+tcp", "https"):
            raise ValueError(f"unsupported SIEM endpoint scheme: {self._u.scheme!r}")
        self._sender = sender or self._default_send
        self.exported = 0

    def _last(self) -> int:
        try:
            return int(json.loads(self._state.read_text("utf-8"))["last_id"])
        except (OSError, ValueError, KeyError):
            return 0

    def _save(self, last_id: int) -> None:
        self._state.parent.mkdir(parents=True, exist_ok=True)
        tmp = self._state.with_suffix(".tmp")
        tmp.write_text(json.dumps({"last_id": last_id}), "utf-8")
        os.replace(tmp, self._state)

    def _default_send(self, rows: list[dict]) -> None:
        s = self._u.scheme
        if s == "https":
            req = urllib.request.Request(
                self._ep, data=json.dumps({"verdicts": rows}).encode("utf-8"),
                headers={"Content-Type": "application/json"}, method="POST")
            tok = os.environ.get(self._token_env or "")
            if tok:
                req.add_header("Authorization", f"Bearer {tok}")
            with urllib.request.urlopen(req, timeout=10) as resp:
                if not 200 <= resp.status < 300:
                    raise OSError(f"SIEM HTTP {resp.status}")
            return
        host, port = self._u.hostname, self._u.port or 514
        data = [(to_cef(r) + "\n").encode("utf-8") for r in rows]
        if s == "syslog+udp":
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                for d in data:
                    sock.sendto(d, (host, port))
        else:
            with socket.create_connection((host, port), timeout=5) as sock:
                sock.sendall(b"".join(data))

    def run_once(self) -> int:
        """Export up to one batch; returns rows exported (0 on idle/failure)."""
        cols = ("id", "ts", "case_id", "incident_id", "outcome", "score",
                "tier", "would")
        rows = [dict(zip(cols, r)) for r in self._store.query(
            "SELECT " + ", ".join(cols) + " FROM decisions WHERE id > ?"
            " ORDER BY id ASC LIMIT ?", (self._last(), self._batch))]
        if not rows:
            return 0
        try:
            self._sender(rows)
        except Exception as exc:                  # outage: retry next cycle
            log.warning("siem_export_failed", error=type(exc).__name__)
            return 0
        self._save(rows[-1]["id"])
        self.exported += len(rows)
        return len(rows)
