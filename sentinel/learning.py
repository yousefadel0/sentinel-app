"""Durable, bounded observation profile for the initial learning period.

The profile is descriptive evidence, never authorization for an action.
"""
from __future__ import annotations

import json
import os
import threading
from collections import Counter
from contextlib import contextmanager
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Callable, Iterable
from uuid import uuid4

from sentinel.timeutil import parse_iso
from sentinel.models import ConfidenceTier, SourceRef

VERSION = 1
MAX_KEYS = 20_000
FEATURES = ("volume", "ports", "protocols", "hosts", "hours", "auth", "signals")
_PROCESS_LOCK = threading.RLock()


def _valid_profile(doc: object) -> bool:
    if not isinstance(doc, dict) or doc.get("version") != VERSION:
        return False
    if type(doc.get("learning_days")) is not int or doc["learning_days"] < 1:
        return False
    if type(doc.get("extend_days")) is not int or doc["extend_days"] < 0:
        return False
    if doc.get("override") not in ("auto", "learning", "active"):
        return False
    if not isinstance(doc.get("days"), dict):
        return False
    if type(doc.get("overflow")) is not int or doc["overflow"] < 0:
        return False
    try:
        parse_iso(doc["started_at"])
        for day, features in doc["days"].items():
            datetime.fromisoformat(day)
            if not isinstance(features, dict) or any(
                    not isinstance(features.get(name), dict) for name in FEATURES):
                return False
            for name in FEATURES:
                if any(not isinstance(key, str) or type(value) is not int or value < 0
                       for key, value in features[name].items()):
                    return False
    except (KeyError, TypeError, ValueError):
        return False
    return True


@contextmanager
def _exclusive(path: Path):
    """Serialize profile writers across threads and Linux/Windows processes."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with _PROCESS_LOCK, path.with_suffix(path.suffix + ".lock").open("a+b") as lock:
        if os.name == "nt":
            import msvcrt
            lock.seek(0)
            if lock.read(1) == b"":
                lock.write(b"\0")
                lock.flush()
            lock.seek(0)
            msvcrt.locking(lock.fileno(), msvcrt.LK_LOCK, 1)
        else:
            import fcntl
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            if os.name == "nt":
                lock.seek(0)
                msvcrt.locking(lock.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(lock.fileno(), fcntl.LOCK_UN)


class LearningProfile:
    def __init__(self, path: str | Path, *, clock: Callable[[], datetime] | None = None,
                 days: int = 14) -> None:
        if days < 1:
            raise ValueError("learning days must be positive")
        self.path = Path(path)
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        with _exclusive(self.path):
            if self.path.exists():
                doc = json.loads(self.path.read_text(encoding="utf-8"))
                if not _valid_profile(doc):
                    raise ValueError("unsupported or invalid learning profile")
                self._doc = doc
                self._mtime_ns = self.path.stat().st_mtime_ns
            else:
                self._doc = {"version": VERSION, "started_at": self._clock().isoformat(),
                             "learning_days": days, "extend_days": 0,
                             "override": "auto", "days": {}, "overflow": 0}
                self._save()

    def _save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temp = self.path.with_suffix(self.path.suffix + ".tmp")
        temp.write_text(json.dumps(self._doc, sort_keys=True), encoding="utf-8")
        os.replace(temp, self.path)
        self._mtime_ns = self.path.stat().st_mtime_ns

    def _reload(self) -> None:
        if self.path.stat().st_mtime_ns != self._mtime_ns:
            doc = json.loads(self.path.read_text(encoding="utf-8"))
            if not _valid_profile(doc):
                raise ValueError("unsupported or invalid learning profile")
            self._doc = doc
            self._mtime_ns = self.path.stat().st_mtime_ns

    @property
    def mode(self) -> str:
        self._reload()
        override = self._doc["override"]
        if override != "auto":
            return override
        start = parse_iso(self._doc["started_at"])
        due = start + timedelta(days=self._doc["learning_days"] + self._doc["extend_days"])
        enough_data = len(self._doc["days"]) >= self._doc["learning_days"]
        return "active" if self._clock() >= due and enough_data else "learning"

    def set_override(self, mode: str) -> None:
        if mode not in ("auto", "learning", "active"):
            raise ValueError("override must be auto, learning or active")
        with _exclusive(self.path):
            self._reload()
            self._doc["override"] = mode
            self._save()

    def extend(self, days: int) -> None:
        if days < 1 or days > 365:
            raise ValueError("extension must be 1..365 days")
        with _exclusive(self.path):
            self._reload()
            self._doc["extend_days"] += days
            self._save()

    def observe(self, alerts: Iterable) -> None:
        with _exclusive(self.path):
            self._observe_locked(alerts)

    def _observe_locked(self, alerts: Iterable) -> None:
        self._reload()
        if self.mode != "learning":
            return  # freeze the trained baseline during active monitoring
        start = parse_iso(self._doc["started_at"])
        now = self._clock()
        changed = False
        for alert in alerts:
            try:
                ts = parse_iso(alert.ts)
            except (TypeError, ValueError):
                continue
            if ts < start or ts > now + timedelta(minutes=5):
                continue
            date = ts.date().isoformat()
            day = self._doc["days"].setdefault(date, {k: {} for k in FEATURES})
            entries = {
                "volume": ("events",), "ports": (str(alert.dst_port),),
                "protocols": (str(alert.protocol),),
                "hosts": (str(alert.src_ip), str(alert.dst_ip)),
                "hours": (str(ts.hour),),
                "auth": ("auth",) if any("auth" in s for s in alert.signals) else (),
                "signals": tuple(str(s) for s in alert.signals),
            }
            for feature, keys in entries.items():
                counts = day[feature]
                for key in keys:
                    if key not in counts and len(counts) >= MAX_KEYS:
                        self._doc["overflow"] += 1
                        continue
                    counts[key] = counts.get(key, 0) + 1
            changed = True
        if changed:
            self._save()

    def anomalies(self, alerts: Iterable) -> list:
        """Flag unseen destination ports/protocols after a complete observation window.

        This is weak evidence and can only propose notification; it never
        authorizes blocking by itself.
        """
        if self.mode != "active" or len(self._doc["days"]) < self._doc["learning_days"]:
            return []
        trained = self.export()["features"]
        found, seen = [], set()
        for alert in alerts:
            if not ({"zeek_conn", "flow_record"} & set(alert.signals)):
                continue
            key = (alert.dst_ip, alert.dst_port, alert.protocol)
            if key in seen:
                continue
            seen.add(key)
            if str(alert.dst_port) in trained["ports"] and alert.protocol in trained["protocols"]:
                continue
            found.append(replace(
                alert, alert_id=str(uuid4()),
                source=SourceRef(adapter="behavioral", ref=f"baseline:{alert.source.ref}"),
                signals=("baseline_anomaly",), confidence_raw=0.55,
                confidence_tier=ConfidenceTier.B))
        return found

    def export(self) -> dict:
        self._reload()
        start = parse_iso(self._doc["started_at"])
        due = start + timedelta(days=self._doc["learning_days"] + self._doc["extend_days"])
        totals = {k: Counter() for k in FEATURES}
        for day in self._doc["days"].values():
            for feature in FEATURES:
                totals[feature].update(day[feature])
        daily_volume = {date: day["volume"].get("events", 0)
                        for date, day in sorted(self._doc["days"].items())}
        today = self._clock().date().isoformat()
        prior = [count for date, count in daily_volume.items() if date < today]
        return {"version": VERSION, "started_at": self._doc["started_at"],
                "active_at": due.isoformat(), "mode": self.mode,
                "learning_days": self._doc["learning_days"],
                "extend_days": self._doc["extend_days"],
                "override": self._doc["override"], "observed_days": len(self._doc["days"]),
                "overflow": self._doc["overflow"],
                "daily_volume": daily_volume,
                "baseline_daily_mean": round(sum(prior) / len(prior), 1) if prior else None,
                "features": {k: dict(v) for k, v in totals.items()}}
