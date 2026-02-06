"""Pytest configuration for harness tests.

Sets up the Python path to include garak.
"""

import sys
from pathlib import Path

import pytest


def pytest_configure(config):
    """Add garak to the Python path before tests run."""
    # Path to garak relative to this file
    harness_dir = Path(__file__).parent.parent
    garak_path = harness_dir.parent.parent.parent / "garak"

    if garak_path.exists():
        # Insert at the beginning to prioritize local garak
        sys.path.insert(0, str(garak_path))
    else:
        raise RuntimeError(f"garak not found at {garak_path}")


@pytest.fixture
def garak_path():
    """Return the path to the garak directory."""
    harness_dir = Path(__file__).parent.parent
    return harness_dir.parent.parent.parent / "garak"
