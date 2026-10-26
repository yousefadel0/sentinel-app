"""Phase 1 — live tailing, live sources, shadow daemon."""
from __future__ import annotations

import json
import os
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import yaml

from sentinel.auditstore.store import Store
from sentinel.capture.live import LiveEveDataSource, LiveZeekDataSource
from sentinel.capture.tail import OffsetStore, TailReader
from sentinel.config.loader import load_config
from sentinel.daemon import Daemon, build_daemon

CFG = Path(__file__).parent / "fixtures" / "valid_config.yaml"


def _append(path: Path, text: str) -> None:
    with open(path, "ab") as fh:
        fh.write(text.encode())


# -- TailReader -------------------------------------------------------------

def test_tail_returns_only_new_complete_lines(tmp_path):
    f = tmp_path / "a.log"
    r = TailReader(f)
    assert r.read_new_lines() == [] and r.exists is False
    _append(f, "one\ntwo\npart")
    assert r.read_new_lines() == ["one", "two"]
    assert r.read_new_lines() == []
    _append(f, "ial\n")
    assert r.read_new_lines() == ["partial"]
    assert r.line_no == 3


def test_tail_persists_offset_across_restart(tmp_path):
    f, st = tmp_path / "a.log", tmp_path / "off.json"
    _append(f, "a\nb\n")
    TailReader(f, state=OffsetStore(st)).read_new_lines()
    _append(f, "c\n")
    r2 = TailReader(f, state=OffsetStore(st))
    assert r2.read_new_lines() == ["c"]


def test_tail_detects_truncation_and_rotation(tmp_path):
    f = tmp_path / "a.log"
    _append(f, "aaaa\nbbbb\n")
    r = TailReader(f)
    r.read_new_lines()
    f.write_text("x\n")                     # truncated copytruncate-style
    assert r.read_new_lines() == ["x"]
    assert r.rotations == 1
    # rename-style rotation (new inode, size may even be larger)
    f.rename(tmp_path / "a.log.1")
    _append(f, "new1\nnew2\nnew3\nnew4\n")
    assert r.read_new_lines() == ["new1", "new2", "new3", "new4"]


def test_tail_start_at_end_skips_history_once(tmp_path):
    f = tmp_path / "a.log"
    _append(f, "old\n")
    r = TailReader(f, start_at_end=True)
    assert r.read_new_lines() == []
    _append(f, "fresh\n")
    assert r.read_new_lines() == ["fresh"]


# -- live sources -----------------------------------------------------------

def _eve(ts: str, sig: str = "scan", src="203.0.113.7", dst="192.168.4.11",
         **extra) -> str:
    ev = {"timestamp": ts, "event_type": "alert", "src_ip": src, "src_port": 4443,
          "dest_ip": dst, "dest_port": 22, "proto": "TCP",
          "alert": {"signature": "x", "severity": 2, "confidence": 0.9},
          "sentinel_signal": sig, **extra}
    return json.dumps(ev) + "\n"


def test_live_eve_incremental_stats_and_malformed(tmp_path):
    f = tmp_path / "eve.json"
    src = LiveEveDataSource(f, signal_key="sentinel_signal")
    assert src.health()["status"] == "down"
    _append(f, _eve("2026-10-20T08:00:01+0000") + "not json\n"
            + json.dumps({"event_type": "stats",
                          "stats": {"capture": {"kernel_drops": 7}}}) + "\n")
    alerts = src.fetch()
    assert len(alerts) == 1 and alerts[0].signals[0] == "scan"
    assert alerts[0].source.ref == "eve.json#1"
    h = src.health()
    assert h["status"] == "healthy" and h["source_type"] == "live_file"
    assert h["packet_drops"] == 7 and h["malformed_lines_skipped"] == 1
    assert src.fetch() == []                      # nothing new
    _append(f, _eve("2026-10-20T08:00:02+0000"))
    assert src.fetch()[0].source.ref == "eve.json#4"


def test_live_health_degraded_when_stale(tmp_path):
    f = tmp_path / "eve.json"
    _append(f, _eve("2026-10-20T08:00:01+0000"))
    old = time.time() - 600
    os.utime(f, (old, old))
    assert LiveEveDataSource(f, stale_after_s=60).health()["status"] == "degraded"


def test_live_zeek_header_survives_restart(tmp_path):
    f, st = tmp_path / "conn.log", tmp_path / "off.json"
    hdr = ("#fields\tts\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\tproto\n"
           "#types\ttime\taddr\tport\taddr\tport\tstring\n")
    _append(f, hdr + "1697792401.5\t10.9.9.9\t1234\t10.0.0.4\t445\ttcp\n")
    s1 = LiveZeekDataSource(f, state=OffsetStore(st))
    a = s1.fetch()
    assert len(a) == 1 and a[0].dst_ip == "10.0.0.4"
    assert a[0].ts.startswith("2023-10-20")       # epoch -> ISO
    _append(f, "1697792402.5\t10.9.9.9\t1235\t10.0.0.4\t445\ttcp\n")
    s2 = LiveZeekDataSource(f, state=OffsetStore(st))   # no header in new lines
    assert len(s2.fetch()) == 1


# -- daemon -----------------------------------------------------------------

def _daemon(tmp_path, now):
    cfg = yaml.safe_load(CFG.read_text())
    cfg["audit_store"] = {"path": str(tmp_path / "audit.sqlite")}
    cp = tmp_path / "cfg.yaml"
    cp.write_text(yaml.safe_dump(cfg))
    store = Store(tmp_path / "audit.sqlite")
    d = build_daemon(load_config(cp), tmp_path, store)
    d._clock = d._engine._clock = lambda: now[0]
    # swap in a signal-aware eve source (harness-private key, like the pilot)
    d._sources[0] = LiveEveDataSource(tmp_path / "eve.json",
                                      signal_key="sentinel_signal")
    return d, store


def test_daemon_decides_once_then_only_on_escalation(tmp_path):
    base = datetime(2026, 10, 20, 8, 0, 0, tzinfo=timezone.utc)
    now = [base + timedelta(seconds=30)]
    d, store = _daemon(tmp_path, now)
    f = tmp_path / "eve.json"

    def ts(sec):
        return (base + timedelta(seconds=sec)).strftime("%Y-%m-%dT%H:%M:%S+0000")

    _append(f, _eve(ts(1)))
    assert d.run_once() == 1                       # first sighting decided
    assert store.count("decisions") == 1
    assert store.rows("decisions")[0]["case_id"] == "live"
    assert d.run_once() == 0                       # no new data, no re-decision
    _append(f, _eve(ts(2)))
    assert d.run_once() == 1                       # count doubled (1 -> 2)
    _append(f, _eve(ts(3), sig="auth_fail_burst"))
    assert d.run_once() == 1                       # new signal family
    assert d.decisions == 3
    d.write_health()
    health = json.loads((tmp_path / "live-health.json").read_text())
    assert health["mode"] == "live_shadow" and health["decisions"] == 3
    store.close()


def test_daemon_survives_failing_source(tmp_path):
    class Boom:
        name = "boom"
        def fetch(self): raise RuntimeError("sensor exploded")
        def health(self): raise RuntimeError("no")

    now = [datetime(2026, 10, 20, 8, 0, 0, tzinfo=timezone.utc)]
    d, store = _daemon(tmp_path, now)
    d._sources.append(Boom())
    assert d.run_once() == 0
    assert any(h.get("status") == "down" for h in d.health())
    store.close()


def test_prune_drops_stale_alerts(tmp_path):
    base = datetime(2026, 10, 20, 8, 0, 0, tzinfo=timezone.utc)
    now = [base + timedelta(seconds=5)]
    d, store = _daemon(tmp_path, now)
    _append(tmp_path / "eve.json", _eve("2026-10-20T08:00:01+0000"))
    d.run_once()
    assert len(d._buffer) == 1
    now[0] = base + timedelta(hours=3)
    d.run_once()
    assert d._buffer == []
    store.close()


def test_cli_run_refuses_without_audit_store(tmp_path, capsys):
    from sentinel.cli import main
    assert main(["--config", str(CFG), "run", "--capture-dir", str(tmp_path)]) == 1
    assert "audit_store.path" in capsys.readouterr().err


def test_cli_run_ui_refused_when_ops_ui_disabled(tmp_path, capsys):
    from sentinel.cli import main
    cfg = yaml.safe_load(CFG.read_text())
    cfg["audit_store"] = {"path": str(tmp_path / "a.sqlite")}
    cp = tmp_path / "c.yaml"
    cp.write_text(yaml.safe_dump(cfg))
    assert main(["--config", str(cp), "run", "--ui",
                 "--capture-dir", str(tmp_path)]) == 1
    assert "ops_ui.enabled is false" in capsys.readouterr().err


def test_locked_engine_delegates(tmp_path):
    now = [datetime(2026, 10, 20, 8, 0, 0, tzinfo=timezone.utc)]
    d, store = _daemon(tmp_path, now)
    assert type(d._engine).__name__ == "LockedEngine"
    assert d._engine.pending_approvals() == {}
    store.close()


def test_metrics_textfile_format(tmp_path):
    now = [datetime(2026, 10, 20, 8, 0, 0, tzinfo=timezone.utc)]
    d, store = _daemon(tmp_path, now)
    d.run_once()
    text = d.metrics_text()
    assert "# TYPE sentinel_decisions_total counter" in text
    assert 'sentinel_source_status{source="eve_json"} 2' in text   # no file yet
    assert text.endswith("\n") and "None" not in text
    d._metrics_path = tmp_path / "sentinel.prom"
    d.write_metrics()
    assert (tmp_path / "sentinel.prom").read_text() == text
    store.close()
