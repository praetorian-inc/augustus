"""Generator runner for invoking garak generators.

This module provides the run_generator function that loads and executes
garak generators, returning structured output for comparison with Go.
"""

import io
import sys
from contextlib import redirect_stdout, redirect_stderr
from pathlib import Path
from typing import Optional

# Ensure garak is in path
_harness_dir = Path(__file__).parent.parent
_garak_path = _harness_dir.parent.parent.parent / "garak"
if str(_garak_path) not in sys.path:
    sys.path.insert(0, str(_garak_path))

from python_harness.schemas import (
    HarnessResult,
    GeneratorOutput,
    create_success_result,
    create_error_result,
)


def run_generator(
    name: str,
    prompt: str,
    generations: int = 1
) -> HarnessResult:
    """Run a garak generator and return structured output.

    Args:
        name: Generator name in format "module.ClassName" (e.g., "test.Blank")
        prompt: The prompt text to send to the generator
        generations: Number of generations to request

    Returns:
        HarnessResult with generator output or error details
    """
    try:
        # Import garak modules
        from garak import _plugins
        from garak.attempt import Message, Turn, Conversation

        # Suppress garak's console output during plugin loading
        stdout_capture = io.StringIO()
        stderr_capture = io.StringIO()

        # Load the generator plugin
        generator_name = f"generators.{name}"
        try:
            with redirect_stdout(stdout_capture), redirect_stderr(stderr_capture):
                generator = _plugins.load_plugin(generator_name)
        except Exception as e:
            return create_error_result(
                capability_type="generator",
                capability_name=name,
                error=f"Generator not found: {name}. Error: {str(e)}"
            )

        # Create a conversation with the prompt
        conversation = Conversation(
            turns=[Turn(role="user", content=Message(text=prompt))]
        )

        # Run the generator
        outputs = generator.generate(conversation, generations_this_call=generations)

        # Extract text from Message objects
        generation_texts = []
        for output in outputs:
            if output is None:
                generation_texts.append(None)
            else:
                generation_texts.append(output.text)

        # Build output structure
        output = GeneratorOutput(
            generations=generation_texts,
            generator_family_name=generator.generator_family_name,
            supports_multiple_generations=generator.supports_multiple_generations,
        )

        return create_success_result(
            capability_type="generator",
            capability_name=name,
            output=output
        )

    except Exception as e:
        return create_error_result(
            capability_type="generator",
            capability_name=name,
            error=f"Error running generator: {str(e)}"
        )
