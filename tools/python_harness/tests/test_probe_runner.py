"""Tests for the probe runner.

Tests the run_probe function against garak's test probes.
"""

import pytest

from python_harness.runners.probe_runner import run_probe
from python_harness.schemas import HarnessResult


class TestProbeRunner:
    """Test cases for run_probe function."""

    def test_run_blank_probe_returns_prompts(self):
        """test.Blank probe should return its prompts."""
        result = run_probe("test.Blank")

        assert isinstance(result, HarnessResult)
        assert result.success is True
        assert result.capability_type == "probe"
        assert result.capability_name == "test.Blank"
        assert result.error is None
        assert result.output is not None
        assert "prompts" in result.output
        # test.Blank has prompts = [""]
        assert result.output["prompts"] == [""]

    def test_run_test_probe_returns_multiple_prompts(self):
        """test.Test probe should return its multiple test prompts."""
        result = run_probe("test.Test")

        assert result.success is True
        assert result.capability_name == "test.Test"
        assert "prompts" in result.output
        # test.Test has 8 prompts including empty, unicode, special chars
        prompts = result.output["prompts"]
        assert len(prompts) == 8
        assert "" in prompts  # Empty string
        assert "The quick brown fox jumps over the lazy dog" in prompts

    def test_run_probe_returns_primary_detector(self):
        """Probe output should include primary detector."""
        result = run_probe("test.Blank")

        assert result.success is True
        assert "primary_detector" in result.output
        # test.Blank uses any.AnyOutput detector
        assert result.output["primary_detector"] == "any.AnyOutput"

    def test_run_test_probe_returns_always_pass_detector(self):
        """test.Test probe should use always.Pass detector."""
        result = run_probe("test.Test")

        assert result.success is True
        assert result.output["primary_detector"] == "always.Pass"

    def test_run_probe_returns_goal(self):
        """Probe output should include the goal."""
        result = run_probe("test.Blank")

        assert result.success is True
        assert "goal" in result.output
        assert len(result.output["goal"]) > 0

    def test_run_probe_with_invalid_name_returns_error(self):
        """Running a non-existent probe should return an error."""
        result = run_probe("nonexistent.Probe")

        assert result.success is False
        assert result.error is not None

    def test_run_probe_with_generator_runs_probe(self):
        """Running probe with generator should execute and return attempts."""
        result = run_probe("test.Blank", generator_name="test.Blank")

        assert result.success is True
        assert "attempts" in result.output
        # When run with generator, should have attempts
        assert len(result.output["attempts"]) > 0

    def test_run_probe_without_generator_returns_prompts_only(self):
        """Running probe without generator should return prompts but no attempts."""
        result = run_probe("test.Blank")

        assert result.success is True
        assert "prompts" in result.output
        # Without generator, attempts should be empty
        assert result.output["attempts"] == []


class TestProbeRunnerEdgeCases:
    """Edge case tests for probe runner."""

    def test_run_probe_prompts_preserve_unicode(self):
        """Probe prompts should preserve Unicode characters."""
        result = run_probe("test.Test")

        assert result.success is True
        prompts = result.output["prompts"]
        # test.Test includes Chinese characters
        unicode_prompt = "有朋自远方来，不亦乐乎?"
        assert unicode_prompt in prompts

    def test_run_probe_prompts_preserve_special_chars(self):
        """Probe prompts should preserve special characters."""
        result = run_probe("test.Test")

        assert result.success is True
        prompts = result.output["prompts"]
        # test.Test includes backslash
        assert "\\" in prompts
