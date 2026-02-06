"""Tests for the detector runner.

Tests the run_detector function against garak's always detectors.
"""

import json
import pytest

from python_harness.runners.detector_runner import run_detector
from python_harness.schemas import HarnessResult


class TestDetectorRunner:
    """Test cases for run_detector function."""

    def test_run_pass_detector_returns_zeros(self):
        """always.Pass detector should return all zeros (pass)."""
        # Create an attempt with outputs
        attempt_data = {
            "prompt": "test prompt",
            "outputs": ["response 1", "response 2"]
        }

        result = run_detector("always.Pass", json.dumps(attempt_data))

        assert isinstance(result, HarnessResult)
        assert result.success is True
        assert result.capability_type == "detector"
        assert result.capability_name == "always.Pass"
        assert result.error is None
        assert result.output is not None
        assert "scores" in result.output
        assert result.output["scores"] == [0.0, 0.0]

    def test_run_fail_detector_returns_ones(self):
        """always.Fail detector should return all ones (fail/hit)."""
        attempt_data = {
            "prompt": "test prompt",
            "outputs": ["response 1", "response 2", "response 3"]
        }

        result = run_detector("always.Fail", json.dumps(attempt_data))

        assert result.success is True
        assert result.capability_name == "always.Fail"
        assert result.output["scores"] == [1.0, 1.0, 1.0]

    def test_run_detector_with_single_output(self):
        """Detector should handle single output."""
        attempt_data = {
            "prompt": "test",
            "outputs": ["single response"]
        }

        result = run_detector("always.Pass", json.dumps(attempt_data))

        assert result.success is True
        assert result.output["scores"] == [0.0]

    def test_run_detector_with_empty_outputs(self):
        """Detector should handle empty outputs list."""
        attempt_data = {
            "prompt": "test",
            "outputs": []
        }

        result = run_detector("always.Pass", json.dumps(attempt_data))

        assert result.success is True
        assert result.output["scores"] == []

    def test_run_detector_with_invalid_name_returns_error(self):
        """Running a non-existent detector should return an error."""
        attempt_data = {
            "prompt": "test",
            "outputs": ["response"]
        }

        result = run_detector("nonexistent.Detector", json.dumps(attempt_data))

        assert result.success is False
        assert result.error is not None

    def test_run_detector_with_invalid_json_returns_error(self):
        """Invalid JSON should return an error."""
        result = run_detector("always.Pass", "not valid json")

        assert result.success is False
        assert result.error is not None
        assert "json" in result.error.lower() or "parse" in result.error.lower()

    def test_run_detector_output_includes_metadata(self):
        """Detector output should include metadata."""
        attempt_data = {
            "prompt": "test",
            "outputs": ["response"]
        }

        result = run_detector("always.Pass", json.dumps(attempt_data))

        assert result.success is True
        assert "detector_name" in result.output
        assert "lang_spec" in result.output
        assert result.output["lang_spec"] == "*"


class TestDetectorRunnerEdgeCases:
    """Edge case tests for detector runner."""

    def test_run_detector_with_unicode_outputs(self):
        """Detector should handle Unicode in outputs."""
        attempt_data = {
            "prompt": "test",
            "outputs": ["Hello, 世界!", "Привет!"]
        }

        result = run_detector("always.Pass", json.dumps(attempt_data))

        assert result.success is True
        assert len(result.output["scores"]) == 2

    def test_run_detector_with_empty_string_outputs(self):
        """Detector should handle empty string outputs."""
        attempt_data = {
            "prompt": "test",
            "outputs": ["", "response", ""]
        }

        result = run_detector("always.Fail", json.dumps(attempt_data))

        assert result.success is True
        assert len(result.output["scores"]) == 3
        assert all(score == 1.0 for score in result.output["scores"])

    def test_run_detector_with_null_outputs(self):
        """Detector should handle null/None outputs."""
        attempt_data = {
            "prompt": "test",
            "outputs": [None, "response", None]
        }

        result = run_detector("always.Pass", json.dumps(attempt_data))

        assert result.success is True
        # Null outputs should result in None scores
        assert len(result.output["scores"]) == 3
