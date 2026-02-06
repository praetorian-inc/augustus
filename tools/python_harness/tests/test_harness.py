"""Tests for the CLI harness entry point.

Tests the harness.py CLI for invoking garak capabilities.
"""

import json
import subprocess
import sys
from pathlib import Path

import pytest


# Path to the harness script
HARNESS_PATH = Path(__file__).parent.parent / "harness.py"
HARNESS_PARENT = Path(__file__).parent.parent.parent  # tools/ directory, parent of python_harness
GARAK_PATH = Path(__file__).parent.parent.parent.parent / "garak"


def run_harness(*args) -> tuple[int, str, str]:
    """Run the harness CLI and return (exit_code, stdout, stderr)."""
    import os
    env = os.environ.copy()
    env["PYTHONPATH"] = f"{GARAK_PATH}:{HARNESS_PARENT}"
    result = subprocess.run(
        [sys.executable, str(HARNESS_PATH)] + list(args),
        capture_output=True,
        text=True,
        env=env
    )
    return result.returncode, result.stdout, result.stderr


class TestHarnessGenerator:
    """Test cases for generator CLI commands."""

    def test_run_generator_blank(self):
        """CLI should run generator and return JSON output."""
        exit_code, stdout, stderr = run_harness(
            "generator", "test.Blank",
            "--prompt", "hello",
            "--generations", "1"
        )

        assert exit_code == 0, f"stderr: {stderr}"
        result = json.loads(stdout)
        assert result["success"] is True
        assert result["capability_type"] == "generator"
        assert result["capability_name"] == "test.Blank"
        assert result["output"]["generations"] == [""]

    def test_run_generator_repeat(self):
        """CLI should run Repeat generator and echo input."""
        exit_code, stdout, stderr = run_harness(
            "generator", "test.Repeat",
            "--prompt", "test message",
            "--generations", "2"
        )

        assert exit_code == 0, f"stderr: {stderr}"
        result = json.loads(stdout)
        assert result["success"] is True
        assert result["output"]["generations"] == ["test message", "test message"]

    def test_run_generator_invalid(self):
        """CLI should return error for invalid generator."""
        exit_code, stdout, stderr = run_harness(
            "generator", "invalid.Generator",
            "--prompt", "test"
        )

        # Should still exit 0 but with error in result
        result = json.loads(stdout)
        assert result["success"] is False
        assert result["error"] is not None


class TestHarnessDetector:
    """Test cases for detector CLI commands."""

    def test_run_detector_pass(self):
        """CLI should run Pass detector and return zeros."""
        attempt_data = json.dumps({
            "prompt": "test",
            "outputs": ["response1", "response2"]
        })
        exit_code, stdout, stderr = run_harness(
            "detector", "always.Pass",
            "--attempt", attempt_data
        )

        assert exit_code == 0, f"stderr: {stderr}"
        result = json.loads(stdout)
        assert result["success"] is True
        assert result["output"]["scores"] == [0.0, 0.0]

    def test_run_detector_fail(self):
        """CLI should run Fail detector and return ones."""
        attempt_data = json.dumps({
            "prompt": "test",
            "outputs": ["response"]
        })
        exit_code, stdout, stderr = run_harness(
            "detector", "always.Fail",
            "--attempt", attempt_data
        )

        assert exit_code == 0, f"stderr: {stderr}"
        result = json.loads(stdout)
        assert result["success"] is True
        assert result["output"]["scores"] == [1.0]


class TestHarnessProbe:
    """Test cases for probe CLI commands."""

    def test_run_probe_blank(self):
        """CLI should run Blank probe and return prompts."""
        exit_code, stdout, stderr = run_harness(
            "probe", "test.Blank"
        )

        assert exit_code == 0, f"stderr: {stderr}"
        result = json.loads(stdout)
        assert result["success"] is True
        assert result["output"]["prompts"] == [""]
        assert result["output"]["primary_detector"] == "any.AnyOutput"

    def test_run_probe_with_generator(self):
        """CLI should run probe with generator."""
        exit_code, stdout, stderr = run_harness(
            "probe", "test.Blank",
            "--generator", "test.Blank"
        )

        assert exit_code == 0, f"stderr: {stderr}"
        result = json.loads(stdout)
        assert result["success"] is True
        assert len(result["output"]["attempts"]) > 0


class TestHarnessHelp:
    """Test cases for help and usage."""

    def test_help_shows_usage(self):
        """CLI should show help with --help."""
        exit_code, stdout, stderr = run_harness("--help")
        # argparse returns 0 for --help
        assert exit_code == 0
        assert "usage" in stdout.lower() or "usage" in stderr.lower()

    def test_no_args_shows_usage(self):
        """CLI without args should show usage."""
        exit_code, stdout, stderr = run_harness()
        # argparse returns error code for missing args
        assert exit_code != 0 or "usage" in stdout.lower() or "error" in stderr.lower()
