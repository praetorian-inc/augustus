# Project Overview

Augustus is a Go-based LLM vulnerability scanner that tests large language models against adversarial attacks. It integrates with many LLM providers and produces actionable vulnerability reports.

Capabilities (probes, generators, detectors, buffs, recon) self-register via `init()` under `internal/` and are blank-imported through `pkg/register`. Public contracts live in `pkg/types/`.
