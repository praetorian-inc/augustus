"""Detector runner for invoking garak detectors.

This module provides the run_detector function that loads and executes
garak detectors, returning structured output for comparison with Go.
"""

import json
import sys
from pathlib import Path
from typing import Optional, List

# Ensure garak is in path
_harness_dir = Path(__file__).parent.parent
_garak_path = _harness_dir.parent.parent.parent / "garak"
if str(_garak_path) not in sys.path:
    sys.path.insert(0, str(_garak_path))

from python_harness.schemas import (
    HarnessResult,
    DetectorOutput,
    create_success_result,
    create_error_result,
)


def run_detector(
    name: str,
    attempt_json: str,
    config_json: str = "{}"
) -> HarnessResult:
    """Run a garak detector and return structured output.

    Args:
        name: Detector name in format "module.ClassName" (e.g., "always.Pass")
        attempt_json: JSON string representing an Attempt object with:
            - prompt: str - The prompt text
            - outputs: List[str | None] - List of output strings
        config_json: JSON string with detector config (e.g., {"substrings": ["test"]})

    Returns:
        HarnessResult with detector scores or error details
    """
    try:
        # Parse the attempt JSON
        try:
            attempt_data = json.loads(attempt_json)
        except json.JSONDecodeError as e:
            return create_error_result(
                capability_type="detector",
                capability_name=name,
                error=f"JSON parse error for attempt: {str(e)}"
            )

        # Parse config JSON
        try:
            config_data = json.loads(config_json) if config_json else {}
        except json.JSONDecodeError as e:
            return create_error_result(
                capability_type="detector",
                capability_name=name,
                error=f"JSON parse error for config: {str(e)}"
            )

        # Import garak modules
        from garak import _plugins
        from garak.attempt import Attempt, Message, Turn, Conversation
        from garak.detectors.base import StringDetector

        # Handle StringDetector specially (requires substrings constructor arg)
        if name == "base.StringDetector":
            substrings = config_data.get("substrings", [])
            matchtype = config_data.get("matchtype", "str")
            case_sensitive = config_data.get("case_sensitive", False)

            detector = StringDetector(substrings=substrings)
            detector.matchtype = matchtype
            # Note: case_sensitive is passed to detect() not stored in detector
        else:
            # Load the detector plugin normally
            detector_name = f"detectors.{name}"
            try:
                detector = _plugins.load_plugin(detector_name)
            except Exception as e:
                return create_error_result(
                    capability_type="detector",
                    capability_name=name,
                    error=f"Detector not found: {name}. Error: {str(e)}"
                )

        # Build an Attempt object from the JSON data
        prompt_text = attempt_data.get("prompt", "")
        outputs = attempt_data.get("outputs", [])

        # Create a conversation for the prompt
        prompt_msg = Message(text=prompt_text)
        conversation = Conversation(
            turns=[Turn(role="user", content=prompt_msg)]
        )

        # Create the Attempt
        attempt = Attempt(prompt=conversation)

        # Set outputs - convert strings to Messages
        output_messages = []
        for output in outputs:
            if output is None:
                output_messages.append(None)
            else:
                output_messages.append(Message(text=output))

        # Set outputs on the attempt (need to expand conversations first if needed)
        if len(output_messages) > 0:
            attempt.outputs = output_messages

        # Run the detector
        # StringDetector.detect() takes case_sensitive parameter
        if name == "base.StringDetector":
            case_sensitive = config_data.get("case_sensitive", False)
            scores = detector.detect(attempt, case_sensitive=case_sensitive)
        else:
            scores = detector.detect(attempt)

        # Convert scores to list (may be generator)
        scores_list: List[Optional[float]] = list(scores)

        # Build output structure
        output = DetectorOutput(
            scores=scores_list,
            detector_name=detector.detectorname,
            lang_spec=detector.lang_spec if detector.lang_spec else "*",
        )

        return create_success_result(
            capability_type="detector",
            capability_name=name,
            output=output
        )

    except Exception as e:
        return create_error_result(
            capability_type="detector",
            capability_name=name,
            error=f"Error running detector: {str(e)}"
        )
