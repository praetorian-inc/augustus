# Changelog

All notable changes to Augustus will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added
- Poetry buff with HarmJudge detector for semantic harm assessment
- MLCommons AILuminate taxonomy with 50+ harmful payloads across 12 categories
- Poetry templates: haiku, sonnet, limerick, free verse, rhyming couplet
- Strategy configuration for poetry buff (5 formats, 3 strategies)

### Fixed
- Haiku template keyword preservation improved to 50%

## [0.3.0] - 2025-12-15

### Added
- PAIR and TAP iterative attack engine with multi-stream conversation management
- Candidate pruning and judge-based scoring for iterative probes
- Buff transformation system (encoding, paraphrase, poetry, translation, case transforms)
- 7 buff categories with composable pipeline

## [0.2.0] - 2025-10-01

### Added
- Expanded to 190+ probes across 47 attack categories
- 28 LLM provider integrations with 43 generator variants
- 90+ detector implementations across 35 categories
- FlipAttack probes (16 variants)
- RAG poisoning framework with metadata injection
- Multi-agent orchestrator and browsing exploit probes
- Guardrail bypass probes (20 variants)
- Rate limiting with token bucket algorithm
- Aho-Corasick pre-filtering for fast keyword matching
- HTML report output format
- YAML probe templates (Nuclei-style)
- Proxy support for traffic inspection (Burp Suite, mitmproxy)
- SSE response parsing for streaming endpoints
- Shell completion (bash, zsh, fish)

### Changed
- Restructured architecture: public interfaces in `pkg/`, implementations in `internal/`

## [0.1.0] - 2025-06-01

### Added
- Initial release
- Core scanner with concurrent probe execution
- CLI with Kong-based argument parsing
- OpenAI, Anthropic, Ollama provider support
- DAN, encoding, and smuggling probe categories
- Pattern matching and LLM-as-a-judge detectors
- Table, JSON, JSONL output formats
- YAML configuration with environment variable interpolation
- Exponential backoff retry logic
- Structured slog-based logging

[Unreleased]: https://github.com/praetorian-inc/augustus/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/praetorian-inc/augustus/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/praetorian-inc/augustus/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/praetorian-inc/augustus/releases/tag/v0.1.0
