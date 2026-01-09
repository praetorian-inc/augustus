# Augustus - LLM Vulnerability Scanner

[![Go Report Card](https://goreportcard.com/badge/github.com/praetorian-inc/augustus)](https://goreportcard.com/report/github.com/praetorian-inc/augustus)
[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Go Version](https://img.shields.io/github/go-mod/go-version/praetorian-inc/augustus)](go.mod)

> **LLM security testing framework** for detecting prompt injection, jailbreaks, and adversarial attacks in AI systems

**Augustus** is a comprehensive Go-based LLM vulnerability scanner designed to test large language models against a wide range of security vulnerabilities and adversarial attacks.

## Table of Contents

- [Why Augustus](#why-augustus)
- [Features](#features)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Configuration](#configuration)
- [Usage Examples](#usage-examples)
- [Supported Providers](#supported-providers)
- [Architecture](#architecture)
- [CLI Reference](#cli-reference)
- [Use Cases](#use-cases)
- [Troubleshooting](#troubleshooting)
- [FAQ](#faq)
- [Development](#development)
- [Contributing](#contributing)
- [License](#license)

## Why Augustus

Augustus fills a critical gap in the LLM security testing landscape by providing:

- **Native Go Performance**: Unlike Python-based alternatives, Augustus offers faster execution, lower memory footprint, and easy cross-platform distribution as a single binary
- **Production-Ready Design**: Built with concurrent scanning, rate limiting, retry logic, and timeout handling for testing production LLM deployments
- **Comprehensive Attack Coverage**: 46+ vulnerability probes covering prompt injection, jailbreaks, encoding exploits, data extraction, and adversarial examples
- **Flexible Integration**: Works with 19 LLM providers out of the box, plus REST API support for custom endpoints
- **Actionable Results**: Multiple output formats (table, JSON, JSONL, HTML) with detailed vulnerability reports

**Compared to alternatives:**

| Feature | Augustus | garak | promptfoo |
|---------|----------|-------|-----------|
| Language | Go | Python | TypeScript |
| Single binary | Yes | No | No |
| Concurrent scanning | Yes | Limited | Yes |
| LLM providers | 19 | 10+ | 15+ |
| Probe types | 46+ | 50+ | Custom |
| Enterprise focus | Yes | Research | Yes |

## Description

Augustus provides security researchers and practitioners with a robust framework for assessing the security posture of LLM systems. It supports testing across 46+ vulnerability probes, integrates with 19 LLM providers, and offers flexible detection capabilities through 28 detector implementations.

## Features

- **46+ Vulnerability Probes**: Comprehensive test coverage across multiple attack categories
  - **Jailbreak attacks**: DAN (Do Anything Now), DAN 11.0, AIM, AntiGPT
  - **Prompt injection**: Encoding (Base64, ROT13, Morse), Tag smuggling, FlipAttack
  - **Adversarial examples**: GCG (Greedy Coordinate Gradient), PAIR, AutoDAN, TAP (Tree of Attack Prompts)
  - **Data extraction**: API key leakage, Package hallucination, PII extraction
  - **Context manipulation**: RAG poisoning, Context overflow, Multimodal attacks
  - **Format exploits**: Markdown injection, YAML/JSON parsing attacks
  - **Evasion techniques**: Obfuscation, Character substitution, Translation-based attacks

- **19 LLM Provider Integrations**:
  - **Major cloud providers**: OpenAI (GPT-3.5, GPT-4), Anthropic (Claude 3), Azure OpenAI, AWS Bedrock, Google Vertex AI
  - **Alternative providers**: Cohere, Mistral, Fireworks, Groq, DeepInfra, NVIDIA NIM
  - **Development platforms**: HuggingFace, Replicate, Together AI, Anyscale, LiteLLM
  - **Local deployment**: Ollama (for self-hosted models)
  - **Custom endpoints**: REST API support for proprietary systems

- **28 Detection Strategies**: Analyze responses using:
  - Pattern matching and signature detection
  - Judge-based evaluation (LLM-as-a-judge)
  - Specialized detectors for specific attack types (DAN, encoding, RAG poisoning)
  - Custom detector composition

- **5 Buff Transformations**: Modify probe prompts with:
  - Character substitution and obfuscation
  - Language translation
  - Format conversion
  - Context augmentation
  - Payload encoding

- **3 Harness Strategies**: Orchestrate probe execution with:
  - Probewise: Run all probes independently
  - Iterative: Multi-turn conversation attacks
  - Custom: Define execution flow

- **Flexible Configuration**:
  - YAML-based configuration files
  - Environment variable support
  - Named profiles for different testing scenarios
  - CLI flag overrides

- **Scanner Orchestration**:
  - Concurrent probe execution with errgroup
  - Rate limiting and retry logic
  - Timeout handling
  - Multiple output formats (table, JSON, JSONL, HTML)

## Installation

Requires Go 1.21 or later.

```bash
go install github.com/praetorian-inc/augustus/cmd/augustus@latest
```

Or build from source:

```bash
git clone https://github.com/praetorian-inc/augustus.git
cd augustus
make build
```

## Quick Start

### List Available Capabilities

```bash
# List all registered probes, detectors, and generators
augustus list
```

### Run a Simple Scan

```bash
# Test OpenAI with a specific probe
export OPENAI_API_KEY="your-api-key"
augustus scan openai.OpenAI \
  --probe dan.Dan \
  --detector dan.DanDetector \
  --verbose
```

### Run Multiple Probes

```bash
# Run all encoding-related probes
augustus scan anthropic.Anthropic \
  --probes-glob "encoding.*" \
  --config '{"model":"claude-3-opus-20240229","temperature":0.7}' \
  --output results.jsonl
```

### Use a Configuration File

```bash
# Run with YAML config
augustus scan openai.OpenAI \
  --all \
  --config-file config.yaml \
  --html report.html
```

## Configuration

### YAML Configuration File

Create a `config.yaml` file:

```yaml
# Runtime configuration
run:
  max_attempts: 3
  timeout: "30s"

# Generator configurations
generators:
  openai.OpenAI:
    model: "gpt-4"
    temperature: 0.7
    api_key: "${OPENAI_API_KEY}"  # Environment variable interpolation

  anthropic.Anthropic:
    model: "claude-3-opus-20240229"
    temperature: 0.5
    api_key: "${ANTHROPIC_API_KEY}"

  ollama.OllamaChat:
    model: "llama3.2:3b"
    temperature: 0.8

# Output configuration
output:
  format: "jsonl"
  path: "./results.jsonl"

# Named profiles for different scenarios
profiles:
  quick:
    run:
      max_attempts: 1
      timeout: "10s"
    generators:
      openai.OpenAI:
        model: "gpt-3.5-turbo"
        temperature: 0.5
    output:
      format: "table"

  thorough:
    run:
      max_attempts: 5
      timeout: "60s"
    generators:
      openai.OpenAI:
        model: "gpt-4"
        temperature: 0.3
    output:
      format: "jsonl"
      path: "./thorough_results.jsonl"
```

### Environment Variables

Configure via environment variables:

```bash
# API Keys
export OPENAI_API_KEY="sk-..."
export ANTHROPIC_API_KEY="sk-ant-..."
export COHERE_API_KEY="..."

# Debug mode
export AUGUSTUS_DEBUG=true

# Run scan
augustus scan openai.OpenAI --probe dan.Dan
```

### CLI Configuration

Pass configuration directly via CLI:

```bash
augustus scan openai.OpenAI \
  --probe encoding.InjectBase64 \
  --detector encoding.EncodingDetector \
  --config '{"model":"gpt-4","temperature":0.7,"api_key":"sk-..."}' \
  --format json \
  --output results.json
```

## Usage Examples

### Example 1: Test for DAN Jailbreak

```bash
augustus scan openai.OpenAI \
  --probe dan.Dan \
  --detector dan.DanDetector \
  --config-file config.yaml \
  --verbose
```

### Example 2: Comprehensive Security Scan

```bash
# Run all probes against Claude
augustus scan anthropic.Anthropic \
  --all \
  --detectors-glob "*" \
  --config '{"model":"claude-3-opus-20240229"}' \
  --timeout 60m \
  --output comprehensive-scan.jsonl \
  --html comprehensive-report.html
```

### Example 3: Test Local Model with Ollama

```bash
# No API key needed for Ollama
augustus scan ollama.OllamaChat \
  --probe encoding.InjectBase64 \
  --probe smuggling.TagSmugglingChat \
  --config '{"model":"llama3.2:3b"}' \
  --format table
```

### Example 4: Batch Testing Multiple Probes

```bash
# Use glob patterns to run related probes
augustus scan openai.OpenAI \
  --probes-glob "encoding.*,smuggling.*,dan.*" \
  --detectors-glob "*" \
  --config-file config.yaml \
  --output batch-results.jsonl
```

### Example 5: Custom Timeout and Retry

```bash
augustus scan anthropic.Anthropic \
  --probe tap.TreeOfAttackPrompts \
  --timeout 10m \
  --config-file config.yaml \
  --verbose
```

## Architecture

Augustus follows Go's standard project layout:

```
augustus/
├── cmd/
│   └── augustus/          # CLI entry point
│       ├── main.go        # Main binary
│       ├── cli.go         # Kong CLI definitions
│       ├── scan.go        # Scan command implementation
│       └── common.go      # Shared CLI utilities
├── pkg/                   # Public packages
│   ├── config/           # Configuration loading (YAML/JSON)
│   ├── scanner/          # Scanner orchestration
│   ├── probes/           # Public probe interfaces
│   ├── generators/       # Public generator interfaces
│   ├── detectors/        # Public detector interfaces
│   ├── registry/         # Capability registration
│   └── results/          # Result types and formatting
├── internal/             # Private implementation
│   ├── probes/          # 40+ probe implementations
│   ├── generators/      # 15+ LLM provider integrations
│   ├── detectors/       # 25+ detector implementations
│   ├── harnesses/       # Test harness implementations
│   └── buffs/           # Probe transformation utilities
├── examples/            # Example configurations
└── docs/                # Documentation
```

### Key Components

- **Probes**: Test implementations that generate adversarial inputs
- **Generators**: LLM provider integrations that send prompts and receive completions
- **Detectors**: Analyze generator responses to identify vulnerabilities
- **Harnesses**: Orchestrate probe execution (e.g., probewise, iterative)
- **Scanner**: Coordinates probes, generators, detectors with concurrency control
- **Registry**: Plugin-style registration system using Go init() functions

## Supported Providers

Augustus includes the following 19 LLM providers:

| Provider           | Generator Name            | Notes                          |
|--------------------|---------------------------|--------------------------------|
| OpenAI             | `openai.OpenAI`           | GPT-3.5, GPT-4, GPT-4 Turbo    |
| Anthropic          | `anthropic.Anthropic`     | Claude 3 (Opus, Sonnet, Haiku) |
| Azure OpenAI       | `azure.Azure`             | Azure-hosted OpenAI models     |
| AWS Bedrock        | `bedrock.Bedrock`         | Claude, Llama, Titan models    |
| Google Vertex AI   | `vertex.Vertex`           | PaLM, Gemini models            |
| Cohere             | `cohere.Cohere`           | Command, Command R models      |
| Replicate          | `replicate.Replicate`     | Cloud-hosted open models       |
| HuggingFace        | `huggingface.HuggingFace` | HF Inference API               |
| Together AI        | `together.Together`       | Fast inference for OSS models  |
| Anyscale           | `anyscale.Anyscale`       | Llama and Mistral hosting      |
| Groq               | `groq.Groq`               | Ultra-fast LPU inference       |
| Mistral            | `mistral.Mistral`         | Mistral API models             |
| Fireworks          | `fireworks.Fireworks`     | Production inference platform  |
| DeepInfra          | `deepinfra.DeepInfra`     | Serverless GPU inference       |
| NVIDIA NIM         | `nim.NIM`                 | NVIDIA AI endpoints            |
| Ollama             | `ollama.OllamaChat`       | Local model hosting            |
| LiteLLM            | `litellm.LiteLLM`         | Unified API proxy              |
| REST API           | `rest.REST`               | Custom REST endpoints          |
| Test               | `test.Test`               | Testing and development        |

All providers are available in the compiled binary. Configure via environment variables or YAML configuration files. See [Configuration](#configuration) for setup details.

## CLI Reference

### Commands

```bash
augustus version              # Print version information
augustus list                 # List available probes, detectors, generators
augustus scan <generator>     # Run vulnerability scan
augustus completion <shell>   # Generate shell completion (bash, zsh, fish)
```

### Scan Command Options

```
Usage: augustus scan <generator> [flags]

Arguments:
  <generator>                 Generator name (e.g., openai.OpenAI, anthropic.Anthropic)

Probe Selection (choose one):
  --probe, -p                 Probe name (repeatable)
  --probes-glob               Comma-separated glob patterns (e.g., "dan.*,encoding.*")
  --all                       Run all registered probes

Detector Selection:
  --detector                  Detector name (repeatable)
  --detectors-glob            Comma-separated glob patterns

Configuration:
  --config-file               Path to YAML config file
  --config, -c                JSON config for generator

Execution:
  --harness                   Harness name (default: probewise.Probewise)
  --timeout                   Overall scan timeout (default: 30m)

Output:
  --format, -f                Output format: table, json, jsonl (default: table)
  --output, -o                JSONL output file path
  --html                      HTML report file path
  --verbose, -v               Verbose output

Global:
  --debug, -d                 Enable debug mode
```

## Use Cases

### Pre-Deployment Security Assessment

Before deploying an LLM-powered application to production, use Augustus to identify vulnerabilities:

```bash
# Comprehensive security scan
augustus scan openai.OpenAI \
  --all \
  --config '{"model":"gpt-4"}' \
  --html security-assessment.html \
  --output detailed-results.jsonl
```

### Red Team Exercises

Security teams can use Augustus to simulate adversarial attacks against LLM systems:

```bash
# Run jailbreak and prompt injection probes
augustus scan anthropic.Anthropic \
  --probes-glob "dan.*,encoding.*,smuggling.*" \
  --config '{"model":"claude-3-opus-20240229"}' \
  --verbose
```

### CI/CD Pipeline Integration

Integrate Augustus into your deployment pipeline to catch regressions:

```bash
# Quick validation scan for CI
augustus scan ollama.OllamaChat \
  --probe dan.Dan \
  --probe encoding.InjectBase64 \
  --config '{"model":"llama3.2:3b"}' \
  --format json \
  --output ci-results.json

# Fail pipeline if vulnerabilities found
if grep -q '"vulnerable":true' ci-results.json; then
  echo "Security vulnerabilities detected!"
  exit 1
fi
```

### Compliance and Audit

Generate audit-ready reports for compliance requirements:

```bash
# Generate HTML report for stakeholders
augustus scan openai.OpenAI \
  --all \
  --config-file production-config.yaml \
  --html audit-report.html \
  --output audit-$(date +%Y%m%d).jsonl
```

## Troubleshooting

### Error: "API rate limit exceeded"

**Symptom**: Scan fails with rate limit errors from LLM provider

**Cause**: Too many concurrent requests or requests per minute

**Solution**:
1. Reduce concurrency in your config file
2. Add delays between probes using `--timeout` flag
3. Use provider-specific rate limit settings in YAML config:
   ```yaml
   generators:
     openai.OpenAI:
       rate_limit: 10  # requests per minute
   ```

### Error: "context deadline exceeded" or "timeout"

**Symptom**: Probes fail with timeout errors

**Cause**: Complex probes (like TAP or PAIR) exceed default timeout

**Solution**:
```bash
# Increase timeout for complex probes
augustus scan openai.OpenAI \
  --probe tap.TreeOfAttackPrompts \
  --timeout 60m \
  --config-file config.yaml
```

### Error: "invalid API key" or "authentication failed"

**Symptom**: Generator fails to authenticate with LLM provider

**Cause**: Missing or invalid API credentials

**Solution**:
1. Verify environment variable is set:
   ```bash
   echo $OPENAI_API_KEY  # Should show your key
   ```
2. Check for typos in config file
3. Ensure API key has required permissions
4. For Ollama, ensure the service is running:
   ```bash
   ollama serve  # Start Ollama server
   ```

### Error: "probe not found" or "detector not found"

**Symptom**: Augustus can't find specified probe or detector

**Cause**: Typo in name or probe not registered

**Solution**:
```bash
# List all available probes and detectors
augustus list

# Use exact names from the list
augustus scan openai.OpenAI --probe dan.Dan  # Correct
```

### Scan produces no results

**Symptom**: Scan completes but output is empty

**Cause**: Detector didn't match any responses, or output not written

**Solution**:
1. Run with `--verbose` to see detailed output
2. Check that detector matches probe type
3. Verify output file path is writable:
   ```bash
   augustus scan openai.OpenAI \
     --probe dan.Dan \
     --detector dan.DanDetector \
     --output ./results.jsonl \
     --verbose
   ```

## FAQ

### How does Augustus compare to garak?

Augustus is a Go-native implementation inspired by garak's approach. Key differences:
- **Performance**: Go binary vs Python interpreter - faster execution and lower memory
- **Distribution**: Single binary with no runtime dependencies
- **Focus**: Production security testing vs research exploration
- **Probes**: Subset of garak's probes, focusing on highest-impact vulnerabilities

### Can I test local models without API keys?

Yes! Use the Ollama integration for local model testing:

```bash
# No API key needed
augustus scan ollama.OllamaChat \
  --probe dan.Dan \
  --config '{"model":"llama3.2:3b"}'
```

### How do I add custom probes?

1. Create a new Go file in `internal/probes/`
2. Implement the `probes.Probe` interface
3. Register using `registry.RegisterProbe()` in an `init()` function
4. Rebuild: `make build`

See [CONTRIBUTING.md](CONTRIBUTING.md) for detailed instructions.

### What output formats are supported?

Augustus supports four output formats:

| Format | Flag | Use Case |
|--------|------|----------|
| Table | `--format table` | Human-readable terminal output |
| JSON | `--format json` | Single JSON object for parsing |
| JSONL | `--format jsonl` | Line-delimited JSON for streaming |
| HTML | `--html report.html` | Visual reports for stakeholders |

### How do I test multiple models at once?

Create a config file with multiple generators and run separate scans:

```bash
# Test multiple models sequentially
for model in "gpt-4" "gpt-3.5-turbo"; do
  augustus scan openai.OpenAI \
    --all \
    --config "{\"model\":\"$model\"}" \
    --output "results-$model.jsonl"
done
```

### Is Augustus suitable for production environments?

Yes, Augustus is designed for production use with:
- Concurrent scanning with configurable limits
- Rate limiting to respect API quotas
- Timeout handling for long-running probes
- Retry logic for transient failures
- Structured logging for observability

## Development

### Running Tests

```bash
# Run all tests
make test

# Run specific package tests
go test ./pkg/scanner -v

# Run equivalence tests (compare Go vs Python implementations)
go test ./tests/equivalence -v
```

### Building

```bash
# Build binary
make build

# Cross-compile for different platforms
make build-all
```

## License

Augustus is licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for the full license text.

---

**Maintained by**: [Praetorian](https://www.praetorian.com/)
