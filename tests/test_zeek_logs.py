"""Zeek TSV reader tests — header handling, coercion, malformed honesty."""
from __future__ import annotations

from pathlib import Path

import pytest

from sentinel.capture.zeek_logs import iter_zeek

FIXTURES = Path(__file__).parent / "fixtures" / "capture"


def test_conn_fixture_rows_and_malformed_row_handling():
    rows = list(iter_zeek(FIXTURES / "zeek_conn.log"))
    assert len(rows) == 3                          # 4 data rows, 1 malformed
    first = rows[0]
    assert first["id.orig_h"] == "203.0.113.7"
    assert first["id.resp_p"] == 22
    assert first["proto"] == "tcp"
    assert first["duration"] == 42.5               # interval coerced to float
    assert first["orig_pkts"] == 48                # count coerced to int


def test_unset_field_becomes_none():
    rows = list(iter_zeek(FIXTURES / "zeek_dns.log"))
    txt_query = rows[1]
    assert txt_query["answers"] is None            # '-' -> None (unset)
    assert txt_query["TTLs"] is None


def test_vector_fields_split_on_set_separator():
    rows = list(iter_zeek(FIXTURES / "zeek_dns.log"))
    assert rows[0]["answers"] == ["10.0.0.4"]
    assert rows[0]["TTLs"] == [300.0]


def test_ssl_and_notice_logs_parse_with_their_own_headers():
    ssl_rows = list(iter_zeek(FIXTURES / "zeek_ssl.log"))
    assert ssl_rows[0]["server_name"] == "beacon.evil.example"
    notice_rows = list(iter_zeek(FIXTURES / "zeek_notice.log"))
    assert notice_rows[0]["note"] == "Scan::Port_Scan"


def test_row_before_header_is_skipped_counted(tmp_path, caplog):
    f = tmp_path / "hdrless.log"
    f.write_text("no\theader\tyet\n#fields\tone\ttwo\n1\t2\n")
    rows = list(iter_zeek(f))
    assert rows == [{"one": "1", "two": "2"}]
    assert any("zeek_row_before_header_skipped" in r.getMessage()
               for r in caplog.records)


def test_bad_numeric_cell_skips_whole_row_structured_log(tmp_path, caplog):
    f = tmp_path / "badnum.log"
    f.write_text(
        "#fields\tts\tduration\n#types\ttime\tinterval\n"
        "1697792401.0\tNOT_A_NUMBER\n1697792402.0\t3.5\n"
    )
    rows = list(iter_zeek(f))
    assert len(rows) == 1 and rows[0]["duration"] == 3.5
    assert any("zeek_bad_cell_skipped" in r.getMessage() for r in caplog.records)


def test_column_count_mismatch_logged_not_raised(tmp_path, caplog):
    f = tmp_path / "shortrow.log"
    f.write_text("#fields\ta\tb\tc\n1\t2\n1\t2\t3\n")
    rows = list(iter_zeek(f))
    assert len(rows) == 1
    assert any("zeek_malformed_row_skipped" in r.getMessage()
               for r in caplog.records)


def test_empty_file_yields_nothing(tmp_path):
    f = tmp_path / "empty.log"
    f.write_text("")
    assert list(iter_zeek(f)) == []
