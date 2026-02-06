"""Output schemas for the Python harness.

These schemas define the JSON structure returned by each runner,
enabling consistent comparison between Go and Python implementations.
"""

from dataclasses import dataclass, field, asdict
from typing import Any, Optional, List
import json


@dataclass
class HarnessResult:
    """Base result structure returned by all runners.

    Attributes:
        success: Whether the capability executed without error
        capability_type: Type of capability (probe, generator, detector)
        capability_name: Name of the capability (e.g., "test.Blank")
        output: Capability-specific output data
        error: Error message if success is False, None otherwise
    """
    success: bool
    capability_type: str
    capability_name: str
    output: Any = None
    error: Optional[str] = None

    def to_json(self) -> str:
        """Serialize to JSON string."""
        return json.dumps(asdict(self), indent=2, default=str)

    def to_dict(self) -> dict:
        """Convert to dictionary."""
        return asdict(self)


@dataclass
class GeneratorOutput:
    """Output structure for generator results.

    Attributes:
        generations: List of generated text responses
        generator_family_name: The generator family (e.g., "Test")
        supports_multiple_generations: Whether generator supports batch generation
    """
    generations: List[Optional[str]]
    generator_family_name: str
    supports_multiple_generations: bool


@dataclass
class DetectorOutput:
    """Output structure for detector results.

    Attributes:
        scores: List of detection scores (0.0 = pass, 1.0 = fail/hit)
        detector_name: Full name of the detector
        lang_spec: Language specification for the detector
    """
    scores: List[Optional[float]]
    detector_name: str
    lang_spec: str


@dataclass
class ProbeOutput:
    """Output structure for probe results.

    Attributes:
        prompts: List of prompts defined by the probe
        primary_detector: Default detector for this probe
        goal: The goal/intent of the probe
        attempts: List of attempt results when run with a generator
    """
    prompts: List[str]
    primary_detector: str
    goal: str
    attempts: List[dict] = field(default_factory=list)


def create_success_result(
    capability_type: str,
    capability_name: str,
    output: Any
) -> HarnessResult:
    """Create a successful result."""
    return HarnessResult(
        success=True,
        capability_type=capability_type,
        capability_name=capability_name,
        output=output if isinstance(output, dict) else asdict(output),
        error=None
    )


def create_error_result(
    capability_type: str,
    capability_name: str,
    error: str
) -> HarnessResult:
    """Create an error result."""
    return HarnessResult(
        success=False,
        capability_type=capability_type,
        capability_name=capability_name,
        output=None,
        error=error
    )
