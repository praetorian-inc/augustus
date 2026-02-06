"""Tests for the generator runner.

Tests the run_generator function against garak's test generators.
"""

import pytest

from python_harness.runners.generator_runner import run_generator
from python_harness.schemas import HarnessResult


class TestGeneratorRunner:
    """Test cases for run_generator function."""

    def test_run_blank_generator_returns_empty_string(self):
        """test.Blank generator should return empty strings."""
        result = run_generator("test.Blank", prompt="hello", generations=1)

        assert isinstance(result, HarnessResult)
        assert result.success is True
        assert result.capability_type == "generator"
        assert result.capability_name == "test.Blank"
        assert result.error is None
        assert result.output is not None
        assert "generations" in result.output
        assert result.output["generations"] == [""]

    def test_run_blank_generator_multiple_generations(self):
        """test.Blank generator should return multiple empty strings."""
        result = run_generator("test.Blank", prompt="hello", generations=3)

        assert result.success is True
        assert result.output["generations"] == ["", "", ""]

    def test_run_repeat_generator_returns_prompt(self):
        """test.Repeat generator should return the input prompt."""
        result = run_generator("test.Repeat", prompt="hello world", generations=1)

        assert result.success is True
        assert result.capability_name == "test.Repeat"
        assert result.output["generations"] == ["hello world"]

    def test_run_repeat_generator_multiple_generations(self):
        """test.Repeat generator should repeat the prompt multiple times."""
        result = run_generator("test.Repeat", prompt="test prompt", generations=3)

        assert result.success is True
        assert result.output["generations"] == ["test prompt", "test prompt", "test prompt"]

    def test_run_generator_with_invalid_name_returns_error(self):
        """Running a non-existent generator should return an error."""
        result = run_generator("nonexistent.Generator", prompt="hello", generations=1)

        assert result.success is False
        assert result.error is not None
        assert "not found" in result.error.lower() or "error" in result.error.lower()

    def test_run_generator_output_includes_metadata(self):
        """Generator output should include metadata about the generator."""
        result = run_generator("test.Blank", prompt="test", generations=1)

        assert result.success is True
        assert "generator_family_name" in result.output
        assert result.output["generator_family_name"] == "Test"
        assert "supports_multiple_generations" in result.output
        assert result.output["supports_multiple_generations"] is True

    def test_run_generator_with_zero_generations(self):
        """Running with zero generations should return empty list."""
        result = run_generator("test.Blank", prompt="test", generations=0)

        assert result.success is True
        assert result.output["generations"] == []

    def test_run_generator_with_empty_prompt(self):
        """Generator should handle empty prompt."""
        result = run_generator("test.Repeat", prompt="", generations=1)

        assert result.success is True
        assert result.output["generations"] == [""]


class TestGeneratorRunnerEdgeCases:
    """Edge case tests for generator runner."""

    def test_run_generator_with_unicode_prompt(self):
        """Generator should handle Unicode characters."""
        result = run_generator("test.Repeat", prompt="Hello, 世界! Привет!", generations=1)

        assert result.success is True
        assert result.output["generations"] == ["Hello, 世界! Привет!"]

    def test_run_generator_with_special_characters(self):
        """Generator should handle special characters."""
        prompt = "Test with special chars: @#$%^&*(){}[]|\\:\";<>?,./`~"
        result = run_generator("test.Repeat", prompt=prompt, generations=1)

        assert result.success is True
        assert result.output["generations"] == [prompt]
