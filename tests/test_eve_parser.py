"""Streaming eve.json parser tests — memory discipline + malformed honesty."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from sentinel.capture.eve_parser import iter_eve

FIXTURES = Path(__file__).parent / "fixtures" / "capture"


def test_fixture_yields_valid_records_and_skips_malformed(caplog):
    records = list(iter_eve(FIXTURES / "sample_eve.jsonl"))
    assert len(records) == 4                      # 5 lines, 1 malformed skipped
    assert {r["event_type"] for r in records} == {
        "alert", "dns", "tls", "flow"}


def test_streaming_never_reads_whole_file(monkeypatch, tmp_path):
    """Path.read_text/read_bytes must NOT be called — line iteration only."""
    big = tmp_path / "big.jsonl"
    rows = [{"timestamp": f"t{i}", "event_type": "flow",
             "src_ip": "10.0.0.1", "dest_ip": "10.0.0.2"} for i in range(500)]
    big.write_text("\n".join(json.dumps(r) for r in rows) + "\n")

    def explode(*a, **kw):  # any whole-file read attempt fails the test
        raise AssertionError("whole-file read attempted (not streaming)")

    monkeypatch.setattr(Path, "read_text", explode)
    monkeypatch.setattr(Path, "read_bytes", explode)
    count = sum(1 for _ in iter_eve(big))
    assert count == 500


def test_malformed_lines_logged_structured_and_counted(tmp_path, caplog):
    bad = tmp_path / "bad.jsonl"
    bad.write_text('{"ok": 1}\nnot json at all\n{"ok": 2}\n')
    records = list(iter_eve(bad))
    assert len(records) == 2
    warnings = [r for r in caplog.records if r.levelname == "WARNING"]
    assert warnings and "eve_malformed_line_skipped" in warnings[0].getMessage()


def test_empty_file_yields_nothing_without_error(tmp_path):
    empty = tmp_path / "empty.jsonl"
    empty.write_text("")
    assert list(iter_eve(empty)) == []


def test_non_object_json_line_is_skipped_as_malformed(tmp_path):
    f = tmp_path / "arr.jsonl"
    f.write_text("[1, 2, 3]\n{\"ok\": true}\n")
    records = list(iter_eve(f))
    assert len(records) == 1 and records[0]["ok"] is True


def test_blank_lines_are_ignored(tmp_path):
    f = tmp_path / "blanks.jsonl"
    f.write_text('\n\n{"a": 1}\n   \n{"b": 2}\n')
    assert len(list(iter_eve(f))) == 2
