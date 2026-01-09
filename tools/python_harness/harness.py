#!/usr/bin/env python3
"""Python harness CLI for testing Augustus Go implementations against garak.

This CLI allows Go tests to invoke garak capabilities and compare outputs
to verify that the Go port matches Python behavior.

Usage:
    python harness.py generator test.Blank --prompt "hello" --generations 3
    python harness.py detector always.Pass --attempt '{"prompt": "test", "outputs": ["response"]}'
    python harness.py probe test.Blank
    python harness.py probe test.Blank --generator test.Blank
"""

import argparse
import sys
from pathlib import Path

# Ensure garak is in path
_harness_dir = Path(__file__).parent
_garak_path = _harness_dir.parent.parent / "garak"
if str(_garak_path) not in sys.path:
    sys.path.insert(0, str(_garak_path))

# Add harness package parent to path so 'python_harness' is importable
_harness_parent = _harness_dir.parent
if str(_harness_parent) not in sys.path:
    sys.path.insert(0, str(_harness_parent))

from python_harness.runners import run_generator, run_detector, run_probe


def main():
    """Main entry point for the harness CLI."""
    parser = argparse.ArgumentParser(
        description="Python harness for testing Augustus Go implementations against garak",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python harness.py generator test.Blank --prompt "hello" --generations 3
  python harness.py generator test.Repeat --prompt "echo this" --generations 1
  python harness.py detector always.Pass --attempt '{"prompt": "test", "outputs": ["response"]}'
  python harness.py detector always.Fail --attempt '{"prompt": "test", "outputs": ["r1", "r2"]}'
  python harness.py probe test.Blank
  python harness.py probe test.Blank --generator test.Blank
        """
    )

    subparsers = parser.add_subparsers(dest="capability_type", required=True)

    # Generator subcommand
    gen_parser = subparsers.add_parser(
        "generator",
        help="Run a garak generator",
        description="Run a garak generator and return structured output"
    )
    gen_parser.add_argument(
        "name",
        help="Generator name (e.g., test.Blank, test.Repeat)"
    )
    gen_parser.add_argument(
        "--prompt", "-p",
        default="",
        help="Prompt text to send to the generator"
    )
    gen_parser.add_argument(
        "--generations", "-n",
        type=int,
        default=1,
        help="Number of generations to request (default: 1)"
    )

    # Detector subcommand
    det_parser = subparsers.add_parser(
        "detector",
        help="Run a garak detector",
        description="Run a garak detector and return detection scores"
    )
    det_parser.add_argument(
        "name",
        help="Detector name (e.g., always.Pass, always.Fail)"
    )
    det_parser.add_argument(
        "--attempt", "-a",
        required=True,
        help="JSON string with attempt data: {\"prompt\": \"...\", \"outputs\": [...]}"
    )
    det_parser.add_argument(
        "--config", "-c",
        default="{}",
        help="JSON string with detector config (e.g., {\"substrings\": [\"test\"]})"
    )

    # Probe subcommand
    probe_parser = subparsers.add_parser(
        "probe",
        help="Run a garak probe",
        description="Run a garak probe and return prompts/attempts"
    )
    probe_parser.add_argument(
        "name",
        help="Probe name (e.g., test.Blank, test.Test)"
    )
    probe_parser.add_argument(
        "--generator", "-g",
        help="Optional generator to use for running the probe"
    )

    args = parser.parse_args()

    # Route to appropriate runner
    if args.capability_type == "generator":
        result = run_generator(
            name=args.name,
            prompt=args.prompt,
            generations=args.generations
        )
    elif args.capability_type == "detector":
        result = run_detector(
            name=args.name,
            attempt_json=args.attempt,
            config_json=args.config
        )
    elif args.capability_type == "probe":
        result = run_probe(
            name=args.name,
            generator_name=args.generator
        )
    else:
        parser.error(f"Unknown capability type: {args.capability_type}")
        return 1

    # Output JSON result
    print(result.to_json())
    return 0


if __name__ == "__main__":
    sys.exit(main())
