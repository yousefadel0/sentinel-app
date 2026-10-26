"""Shared pytest fixtures for the Sentinel test suite."""
from __future__ import annotations

import shutil
from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture()
def valid_config_path() -> Path:
    return FIXTURES / "valid_config.yaml"


@pytest.fixture()
def invalid_dir() -> Path:
    return FIXTURES / "invalid"


@pytest.fixture()
def tmp_valid_config(tmp_path: Path) -> Path:
    """Copy of the canonical valid config in a tmp dir (for mutation tests)."""
    target = tmp_path / "config.yaml"
    shutil.copy(FIXTURES / "valid_config.yaml", target)
    return target
