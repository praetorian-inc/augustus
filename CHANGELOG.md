# Changelog

All notable changes to Augustus will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

## [0.0.6] - 2026-02-09

### Added
- `flipattack.FullAttack` adversarial probe with paper-faithful framing (arXiv:2410.02832)
- Dynamic few-shot generation in `Full` guidance variant (splits actual payload for demonstrations)

### Changed
- Few-shot examples now derive from input payload instead of static "apple pie" demonstrations

## [0.0.5] - 2026-02-08

### Added
- FlipAttack buffs: `flip.WordOrder`, `flip.CharsInWord`, `flip.CharsInSentence`, `flip.FoolModel` with configurable guidance variants (vanilla, cot, cot_langgpt, full)

### Changed
- Migrated 16 FlipAttack probes to 4 configurable buffs for composability via `--buff` flag

### Removed
- `flipattack.*` probes (16 variants replaced by 4 configurable flip buffs)

## [0.0.4] - 2026-02-08

### Added
- Smuggling buffs: `smuggling.Hypothetical` and `smuggling.FunctionMask` as composable prompt transformations

### Changed
- Migrated smuggling techniques from probes to buffs for composability via `--buff` flag

### Removed
- `smuggling.HypotheticalResponse` and `smuggling.FunctionMasking` probes (replaced by smuggling buffs)

## [0.0.3] - 2026-02-08

### Changed
- Migrated 13 encoding probes to buff architecture (ascii85, base16, base2048, base32, braille, ecoji, hex, morse, rot13, sneaky_bits, unicode_tags, uuencode, zalgo)
- Created `internal/encoding/` package with shared pure functions for reuse

### Removed
- Klingon encoding (will be re-implemented with LLM-based translation)
- `internal/probes/encoding/` package (all probes migrated to buffs)

### Fixed
- Error check for writer.Write() in QuotedPrintable buff

## [0.0.2] - 2026-02-07

### Added
- BaseConfig shared configuration struct for generators
- Credential masking in logs (API keys show prefix + suffix only)
- LLM security classification framework

### Changed
- Migrated 14 generators to BaseConfig pattern: DeepInfra, Fireworks, Together, NIM, Groq, Cerebras, Perplexity, Lepton, Hyperbolic, SambaNova, XAI, OpenRouter, LMStudio, Cloudflare
- Reduced ~800 lines of boilerplate across generator implementations
- ISP (Internal Service Provider) refactor

## [0.0.1] - 2026-02-06

### Added
- Initial public release of Augustus LLM Vulnerability Scanner
- Core scanner with concurrent probe execution
- CLI with Kong-based argument parsing
- 190+ probes across 47 attack categories
- 28 LLM provider integrations with 43 generator variants (OpenAI, Anthropic, Ollama, Bedrock, Replicate, and more)
- 90+ detector implementations across 35 categories
- Pattern matching and LLM-as-a-judge detectors
- HarmJudge detector for semantic harm assessment
- MLCommons AILuminate taxonomy with 50+ harmful payloads across 12 categories
- PAIR and TAP iterative attack engine with multi-stream conversation management
- Candidate pruning and judge-based scoring for iterative probes
- Buff transformation system (encoding, paraphrase, poetry, translation, case transforms)
- Poetry probes with 5 formats (haiku, sonnet, limerick, free verse, rhyming couplet) and 3 strategies
- 7 buff categories with composable pipeline
- FlipAttack probes (16 variants)
- RAG poisoning framework with metadata injection
- Multi-agent orchestrator and browsing exploit probes
- Guardrail bypass probes (20 variants)
- Rate limiting with token bucket algorithm
- Aho-Corasick pre-filtering for fast keyword matching
- Table, JSON, JSONL, HTML output formats
- YAML probe templates (Nuclei-style)
- YAML configuration with environment variable interpolation
- Proxy support for traffic inspection (Burp Suite, mitmproxy)
- SSE response parsing for streaming endpoints
- Shell completion (bash, zsh, fish)
- Exponential backoff retry logic
- Structured slog-based logging

[Unreleased]: https://github.com/praetorian-inc/augustus/compare/v0.0.6...HEAD
[0.0.6]: https://github.com/praetorian-inc/augustus/compare/v0.0.5...v0.0.6
[0.0.5]: https://github.com/praetorian-inc/augustus/compare/v0.0.4...v0.0.5
[0.0.4]: https://github.com/praetorian-inc/augustus/compare/v0.0.3...v0.0.4
[0.0.3]: https://github.com/praetorian-inc/augustus/compare/v0.0.2...v0.0.3
[0.0.2]: https://github.com/praetorian-inc/augustus/compare/v0.0.1...v0.0.2
[0.0.1]: https://github.com/praetorian-inc/augustus/releases/tag/v0.0.1
