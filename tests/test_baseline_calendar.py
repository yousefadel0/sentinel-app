"""D2 discipline for seasonal_calendar.yaml (reminder #3).

Every failure class refuses boot via ConfigError — the SAME exception and
EXACT message format as the main config loader:
offending key + valid keys + "(ref §8)".
"""
from __future__ import annotations

import logging

import pytest
import yaml

from sentinel.baseline.calendar import load_seasonal_calendar
from sentinel.config.loader import ConfigError

REF = "(ref §8)"
VALID_KEYS_ENTRY = "end_date, multipliers, start_date"
VALID_KEYS_TOP = "overrides"


def write(tmp_path, text: str):
    p = tmp_path / "seasonal_calendar.yaml"
    p.write_text(text, encoding="utf-8")
    return p


# ------------------------------------------------------------ happy paths


def test_valid_calendar_loads_with_per_family_multipliers(tmp_path):
    p = write(
        tmp_path,
        "overrides:\n"
        "  - start_date: '2026-12-20'\n"
        "    end_date: '2026-12-26'\n"
        "    multipliers: {scan: 1.5, auth_fail_burst: 2.0}\n",
    )
    overrides, warnings = load_seasonal_calendar(p)
    assert warnings == []
    assert len(overrides) == 1
    ov = overrides[0]
    assert (ov.start.isoformat(), ov.end.isoformat()) == ("2026-12-20", "2026-12-26")
    assert ov.multipliers == {"scan": 1.5, "auth_fail_burst": 2.0}


def test_absent_file_yields_neutral_and_one_structured_warning(caplog):
    with caplog.at_level(logging.WARNING, logger="sentinel.baseline.calendar"):
        overrides, warnings = load_seasonal_calendar("/nonexistent/cal.yaml")
    assert overrides == []                        # neutral multipliers apply
    assert len(warnings) == 1                     # exactly ONE warning line
    assert warnings[0].startswith("seasonal_calendar_absent")
    assert "neutral" in warnings[0]
    structured = [r for r in caplog.records
                  if r.getMessage() == "seasonal_calendar_absent"]
    assert len(structured) == 1          # same warning emitted as JSON log


def test_none_path_is_explicit_no_overrides_no_warnings():
    overrides, warnings = load_seasonal_calendar(None)
    assert overrides == [] and warnings == []


def test_empty_yaml_file_behaves_like_absent(tmp_path):
    p = write(tmp_path, "")
    overrides, warnings = load_seasonal_calendar(p)
    assert overrides == [] and warnings == []


# ------------------------------------------------------- refuse-boot matrix


@pytest.mark.parametrize(
    ("content", "offending"),
    [
        # unknown top-level key
        (
            "overrides: []\nextra_top: true\n",
            "unknown top-level key(s) extra_top; "
            f"valid keys: {VALID_KEYS_TOP} {REF}",
        ),
        # unknown extra key inside an entry
        (
            "overrides:\n"
            "  - start_date: '2026-12-20'\n"
            "    end_date: '2026-12-26'\n"
            "    multipliers: {scan: 1.5}\n"
            "    note: why\n",
            "unknown key(s) note; valid keys: "
            f"{VALID_KEYS_ENTRY} {REF}",
        ),
        # missing required date field
        (
            "overrides:\n"
            "  - start_date: '2026-12-20'\n"
            "    multipliers: {scan: 1.5}\n",
            "required key(s) missing: end_date",
        ),
        # invalid ISO date
        (
            "overrides:\n"
            "  - start_date: '20-12-2026'\n"
            "    end_date: '2026-12-26'\n"
            "    multipliers: {scan: 1.5}\n",
            "invalid ISO date '20-12-2026'",
        ),
        # end < start cross-field violation
        (
            "overrides:\n"
            "  - start_date: '2026-12-26'\n"
            "    end_date: '2026-12-20'\n"
            "    multipliers: {scan: 1.5}\n",
            "end_date='2026-12-20' must be >= start_date='2026-12-26'",
        ),
        # multiplier zero / negative
        (
            "overrides:\n"
            "  - start_date: '2026-12-20'\n"
            "    end_date: '2026-12-26'\n"
            "    multipliers: {scan: 0}\n",
            "multiplier must be a finite float > 0, got 0.0",
        ),
        (
            "overrides:\n"
            "  - start_date: '2026-12-20'\n"
            "    end_date: '2026-12-26'\n"
            "    multipliers: {scan: -2.5}\n",
            "multiplier must be a finite float > 0, got -2.5",
        ),
        # NaN / inf multipliers
        (
            "overrides:\n"
            "  - start_date: '2026-12-20'\n"
            "    end_date: '2026-12-26'\n"
            "    multipliers: {scan: .nan}\n",
            "multiplier must be a finite float > 0, got nan",
        ),
        (
            "overrides:\n"
            "  - start_date: '2026-12-20'\n"
            "    end_date: '2026-12-26'\n"
            "    multipliers: {scan: .inf}\n",
            "multiplier must be a finite float > 0, got inf",
        ),
        # string multiplier
        (
            "overrides:\n"
            "  - start_date: '2026-12-20'\n"
            "    end_date: '2026-12-26'\n"
            "    multipliers: {scan: 'high'}\n",
            "multiplier must be a finite float > 0, got 'high' (str)",
        ),
        # bool multiplier (bool is an int subclass — reject explicitly)
        (
            "overrides:\n"
            "  - start_date: '2026-12-20'\n"
            "    end_date: '2026-12-26'\n"
            "    multipliers: {scan: true}\n",
            "multiplier must be a finite float > 0, got True (bool)",
        ),
        # entry not a mapping
        (
            "overrides:\n"
            "  - just_a_string\n",
            "expected a mapping, got str; "
            f"valid keys: {VALID_KEYS_ENTRY} {REF}",
        ),
        # overrides section not a list
        (
            "overrides: {a: b}\n",
            "expected a list of override entries, got dict",
        ),
        # top level not a mapping
        ("- a\n- b\n", "expected a YAML mapping at top level, got list"),
    ],
)
def test_invalid_calendar_refuses_boot_with_shared_error_format(
    tmp_path, content, offending
):
    p = write(tmp_path, content)
    with pytest.raises(ConfigError) as excinfo:
        load_seasonal_calendar(p)
    msg = str(excinfo.value)
    assert offending in msg          # names the offending key/value...
    assert REF in msg                # ...and cites §8 — shared format


def test_missing_overrides_section_refuses(tmp_path):
    p = write(tmp_path, "something_else: []\n")
    with pytest.raises(ConfigError) as excinfo:
        load_seasonal_calendar(p)
    assert "unknown top-level key(s) something_else" in str(excinfo.value)


def test_invalid_yaml_syntax_refuses(tmp_path):
    p = write(tmp_path, "overrides: [unclosed\n  bad: :\n")
    with pytest.raises(ConfigError) as excinfo:
        load_seasonal_calendar(p)
    assert "invalid YAML syntax" in str(excinfo.value)


# ------------------------------------------------------------- overlap warn


def test_overlap_last_in_file_wins_with_warning_line(tmp_path, caplog):
    """Reminder #2 (calendar side): deterministic winner + warning."""
    p = write(
        tmp_path,
        "overrides:\n"
        "  - start_date: '2026-09-01'\n"
        "    end_date: '2026-09-30'\n"
        "    multipliers: {scan: 3.0}\n"
        "  - start_date: '2026-09-10'\n"
        "    end_date: '2026-09-20'\n"
        "    multipliers: {scan: 1.5}\n",
    )
    with caplog.at_level(logging.WARNING, logger="sentinel.baseline.calendar"):
        overrides, warnings = load_seasonal_calendar(p)
    assert len(warnings) == 1
    assert "LATER entry (index 1) wins" in warnings[0]
    structured = [r for r in caplog.records if r.getMessage() == "seasonal_calendar_overlap"]
    assert len(structured) == 1
    # both entries still returned; engine resolves deterministically by order
    assert len(overrides) == 2


def test_adjacent_not_overlapping_entries_no_warning(tmp_path):
    p = write(
        tmp_path,
        "overrides:\n"
        "  - start_date: '2026-09-01'\n"
        "    end_date: '2026-09-10'\n"
        "    multipliers: {scan: 2.0}\n"
        "  - start_date: '2026-09-11'\n"
        "    end_date: '2026-09-20'\n"
        "    multipliers: {scan: 3.0}\n",
    )
    _, warnings = load_seasonal_calendar(p)
    assert warnings == []
