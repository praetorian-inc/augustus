"""Probe runner for invoking garak probes.

This module provides the run_probe function that loads and executes
garak probes, returning structured output for comparison with Go.
"""

import io
import sys
from contextlib import redirect_stdout, redirect_stderr
from pathlib import Path
from typing import Optional, List

# Ensure garak is in path
_harness_dir = Path(__file__).parent.parent
_garak_path = _harness_dir.parent.parent.parent / "garak"
if str(_garak_path) not in sys.path:
    sys.path.insert(0, str(_garak_path))

from python_harness.schemas import (
    HarnessResult,
    ProbeOutput,
    create_success_result,
    create_error_result,
)


def run_probe(
    name: str,
    generator_name: Optional[str] = None
) -> HarnessResult:
    """Run a garak probe and return structured output.

    Args:
        name: Probe name in format "module.ClassName" (e.g., "test.Blank")
        generator_name: Optional generator name to use for running the probe.
            If None, only probe metadata (prompts, detector, goal) is returned.
            If provided, the probe is executed and attempts are returned.

    Returns:
        HarnessResult with probe output or error details
    """
    try:
        # Import garak modules
        from garak import _plugins, _config
        from garak.attempt import Message

        # Suppress garak's console output during plugin loading
        stdout_capture = io.StringIO()
        stderr_capture = io.StringIO()

        # Load the probe plugin
        probe_name = f"probes.{name}"
        try:
            with redirect_stdout(stdout_capture), redirect_stderr(stderr_capture):
                probe = _plugins.load_plugin(probe_name)
        except Exception as e:
            return create_error_result(
                capability_type="probe",
                capability_name=name,
                error=f"Probe not found: {name}. Error: {str(e)}"
            )

        # Extract prompts - handle both str and Message types
        prompts: List[str] = []
        for p in probe.prompts:
            if isinstance(p, str):
                prompts.append(p)
            elif isinstance(p, Message):
                prompts.append(p.text if p.text else "")
            else:
                prompts.append(str(p))

        # Get primary detector
        primary_detector = probe.primary_detector if probe.primary_detector else ""

        # Get goal
        goal = probe.goal if probe.goal else ""

        # If no generator, just return probe metadata
        attempts_data: List[dict] = []

        if generator_name:
            # Load the generator and run the probe
            gen_plugin_name = f"generators.{generator_name}"
            try:
                with redirect_stdout(stdout_capture), redirect_stderr(stderr_capture):
                    generator = _plugins.load_plugin(gen_plugin_name)
            except Exception as e:
                return create_error_result(
                    capability_type="probe",
                    capability_name=name,
                    error=f"Generator not found: {generator_name}. Error: {str(e)}"
                )

            # Set up minimal config for probe execution
            # Need to provide a dummy report file
            import tempfile
            import os

            # Create a temporary file for the report
            temp_report = tempfile.NamedTemporaryFile(
                mode='w',
                suffix='.jsonl',
                delete=False
            )
            temp_report_path = temp_report.name

            try:
                # Set up transient config for report file
                if not hasattr(_config, 'transient'):
                    _config.transient = type('obj', (object,), {})()
                _config.transient.reportfile = temp_report

                # Set up buffmanager (required by probe)
                if not hasattr(_config, 'buffmanager'):
                    _config.buffmanager = type('obj', (object,), {'buffs': []})()
                elif not hasattr(_config.buffmanager, 'buffs'):
                    _config.buffmanager.buffs = []

                # Set required probe attributes that come from config
                if not hasattr(probe, 'parallel_attempts'):
                    probe.parallel_attempts = 1
                if not hasattr(probe, 'max_workers'):
                    probe.max_workers = 1
                if not hasattr(probe, 'generations'):
                    probe.generations = 1
                if not hasattr(probe, 'soft_probe_prompt_cap'):
                    probe.soft_probe_prompt_cap = 100

                # Run the probe with the generator
                with redirect_stdout(stdout_capture), redirect_stderr(stderr_capture):
                    attempts = probe.probe(generator)

                # Extract attempt data
                for attempt in attempts:
                    attempt_dict = {
                        "prompt": attempt.prompt.turns[-1].content.text if attempt.prompt and attempt.prompt.turns else "",
                        "outputs": [
                            out.text if out else None
                            for out in attempt.outputs
                        ],
                        "goal": attempt.goal,
                    }
                    attempts_data.append(attempt_dict)

            finally:
                # Clean up temp file
                temp_report.close()
                if os.path.exists(temp_report_path):
                    os.unlink(temp_report_path)

        # Build output structure
        output = ProbeOutput(
            prompts=prompts,
            primary_detector=primary_detector,
            goal=goal,
            attempts=attempts_data,
        )

        return create_success_result(
            capability_type="probe",
            capability_name=name,
            output=output
        )

    except Exception as e:
        return create_error_result(
            capability_type="probe",
            capability_name=name,
            error=f"Error running probe: {str(e)}"
        )
