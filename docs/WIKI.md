# Augustus Wiki - Complete Reference

## Table of Contents

- [Overview](#overview)
- [Probes (46+)](#probes-46)
  - [Jailbreak & Prompt Injection](#jailbreak--prompt-injection)
  - [Adversarial & Research-Based](#adversarial--research-based)
  - [Data Extraction](#data-extraction)
  - [Content & Behavior](#content--behavior)
  - [Multimodal & Vision](#multimodal--vision)
  - [Obfuscation & Encoding](#obfuscation--encoding)
  - [Advanced Attack Vectors](#advanced-attack-vectors)
- [Generators (19)](#generators-19)
- [Detectors (28)](#detectors-28)
  - [Pattern & Signature Detection](#pattern--signature-detection)
  - [Jailbreak & Behavior Detection](#jailbreak--behavior-detection)
  - [Content Safety Detection](#content-safety-detection)
  - [LLM-as-a-Judge Detection](#llm-as-a-judge-detection)
  - [Specialized Detection](#specialized-detection)
- [Buffs (5)](#buffs-5)
- [Harnesses (3)](#harnesses-3)
- [Configuration Reference](#configuration-reference)
- [CLI Reference](#cli-reference)
- [Architecture](#architecture)

## Overview

**Augustus** is a comprehensive Go-based LLM vulnerability scanner designed to test large language models against a wide range of security vulnerabilities and adversarial attacks. Built with native Go performance, Augustus offers faster execution, lower memory footprint, and easy cross-platform distribution as a single binary.

**Key Features:**
- 46+ vulnerability probes across multiple attack categories
- 19 LLM provider integrations (OpenAI, Anthropic, Azure, AWS Bedrock, etc.)
- 28 detection strategies for analyzing responses
- 5 buff transformations for probe modification
- 3 harness strategies for orchestrating probe execution
- YAML-based configuration with environment variable support
- Multiple output formats (table, JSON, JSONL, HTML)
- Concurrent scanning with rate limiting and retry logic

**Project Goals:**
- Achieve 100% parity with garak (Python-based LLM security scanner)
- Implement cutting-edge attack techniques from 2024-2026 security research
- Provide production-ready security testing for LLM deployments
- Enable CI/CD pipeline integration for continuous security validation

## Probes (46+)

Augustus implements 46+ vulnerability probes organized by attack category. Probes generate adversarial inputs to test LLM security posture.

### Jailbreak & Prompt Injection

**DAN (Do Anything Now) Variants (~20+)**
- `dan.Dan` - Classic DAN 11.0 jailbreak
- `dan.DanInTheWild` - Real-world DAN variants
- `dan.DanInTheWildFull` - Extended DAN collection
- `dan.AutoDAN` - Automated DAN with genetic algorithms
- `dan.AutoDANCached` - Cached AutoDAN variants
- `dan.Ablation_Dan_11_0` - Ablation study variants
- Multiple YAML template variants loaded at runtime

**Description:** DAN jailbreaks trick LLMs into ignoring safety guidelines by establishing alternate personas that claim to bypass restrictions. These probes test whether the model maintains its safety boundaries when presented with role-playing scenarios.

**FlipAttack (16 variants)**
- Character-level word flipping (4 guidance modes)
- Word-level sentence flipping (4 guidance modes)
- Sentence-level paragraph flipping (4 guidance modes)
- Semantic flipping (4 guidance modes)
- Source: Keysight 2025 / arXiv:2410.02832
- Success rate: 98% vs GPT-4o

**Description:** FlipAttack reverses words, sentences, or semantic meaning to bypass content filters while preserving intent. The model must process reversed text, which often circumvents safety checks.

**Encoding-Based Injection (16 types)**
- `encoding.InjectBase64` - Base64 encoded prompts
- `encoding.InjectBase32` - Base32 encoded prompts
- `encoding.InjectHex` - Hexadecimal encoded prompts
- `encoding.InjectMorse` - Morse code encoded prompts
- `encoding.InjectROT13` - ROT13 cipher encoded prompts
- `encoding.InjectASCII85` - ASCII85 encoded prompts
- `encoding.InjectUUEncode` - UUEncode encoded prompts
- `encoding.InjectQP` - Quoted-Printable encoded prompts
- `encoding.InjectMime` - MIME encoded prompts
- `encoding.InjectNato` - NATO phonetic alphabet
- `encoding.InjectUnicodeEscape` - Unicode escape sequences
- `encoding.InjectPunycode` - Punycode encoded prompts
- `encoding.InjectURLEncode` - URL encoded prompts
- `encoding.InjectHTMLEntity` - HTML entity encoded prompts
- `encoding.InjectZalgo` - Zalgo text (combining diacritics)
- `encoding.InjectBinary` - Binary encoded prompts

**Description:** These probes encode malicious prompts using various encoding schemes. LLMs that decode and process these inputs may inadvertently bypass content filters.

**TAP (Tree of Attacks with Pruning)**
- `tap.TreeOfAttackPrompts` - Multi-turn iterative jailbreak
- Source: arXiv research
- Uses tree search to explore attack space

**Description:** TAP generates a tree of potential attack prompts, pruning unsuccessful branches and expanding promising ones. This iterative approach finds effective jailbreaks through systematic exploration.

**LMRC (Language Model Risk Cards)**
- `lmrc.DirectInject` - Direct prompt injection
- `lmrc.ContextInject` - Context manipulation injection
- `lmrc.RoleConfusion` - Role confusion attacks
- `lmrc.Bullying` - Bullying scenario tests
- `lmrc.Deadnaming` - Deadnaming scenario tests
- 9 total probe variants

**Description:** LMRC probes test LLM behavior across social harm scenarios, including bullying, deadnaming, and role confusion. These assess whether models maintain ethical boundaries.

**PAIR (Prompt Automatic Iterative Refinement)**
- `pair.PAIR` - Automated prompt mutation
- Multi-turn conversation attack
- Adaptive refinement based on responses

**Description:** PAIR automatically refines attack prompts based on model responses, iteratively improving the attack until successful jailbreak or max attempts reached.

**ObscurePrompt**
- `obscureprompt.ObscurePrompt` - LLM-driven prompt mutations
- Uses language models to generate obfuscated variants

**Description:** Uses an LLM to generate creative obfuscations of attack prompts, making them harder for safety systems to detect.

**Poetry Jailbreaks (5 formats)**
- `poetry.Haiku` - Haiku poetry format
- `poetry.Sonnet` - Sonnet poetry format
- `poetry.Limerick` - Limerick poetry format
- `poetry.FreeVerse` - Free verse poetry format
- `poetry.Couplet` - Couplet poetry format
- Source: arXiv:2511.15304
- Success rate: ≥10% improvement over prose

**Description:** Frames malicious prompts as poetry, which can bypass safety filters that focus on prose. Poetry structure adds obfuscation while preserving semantic intent.

### Adversarial & Research-Based

**GCG (Greedy Coordinate Gradient)**
- `gcg.GCG` - Gradient-based adversarial suffix generation
- Optimizes token-level perturbations
- Source: arXiv research on adversarial attacks

**Description:** GCG uses gradient information to craft adversarial suffixes that, when appended to prompts, maximize the likelihood of unsafe responses.

**AutoDAN**
- `autodan.AutoDAN` - Automated DAN with genetic algorithms
- Evolutionary optimization of jailbreak prompts
- Population-based search

**Description:** AutoDAN applies genetic algorithms to evolve effective jailbreak prompts. It maintains a population of prompts, mutates successful variants, and selects for effectiveness.

**Adversarial Patches (3 types)**
- `advpatch.TypedPatch` - Typed adversarial patches
- `advpatch.BlindPatch` - Blind adversarial patches
- `advpatch.UniversalPatch` - Universal adversarial patches
- For vision-language models (VLMs)

**Description:** Adversarial patches are images designed to fool VLMs. When added to images, they can cause misclassification or bypass content moderation.

**Goodside Injection Techniques**
- `goodside.Goodside` - Riley Goodside's prompt injection techniques
- Real-world injection patterns
- Based on production attack examples

**Description:** Named after security researcher Riley Goodside, these probes replicate real-world prompt injection patterns observed in production systems.

**Latent Injection (3 variants)**
- `latentinjection.Basic` - Basic latent space injection
- `latentinjection.Advanced` - Advanced latent manipulation
- `latentinjection.Deep` - Deep latent space attacks

**Description:** Latent injection attacks manipulate model activations in hidden layers, bypassing surface-level safety checks by operating in the model's internal representation space.

### Data Extraction

**API Key Extraction**
- `apikey.GetKey` - Direct API key extraction
- `apikey.CompleteKey` - API key completion attacks
- Tests model's propensity to leak credentials
- 58 prompts covering various API key types

**Description:** These probes test whether the model will reveal API keys, credentials, or other sensitive information embedded in training data or context.

**Package Hallucination**
- Package name generation for various ecosystems
- Tests model's tendency to invent non-existent packages
- Can lead to supply chain attacks

**Description:** LLMs sometimes hallucinate package names that don't exist. Attackers can register these packages with malicious code, exploiting developers who trust LLM suggestions.

### Content & Behavior

**Continuation Attacks**
- `continuation.SlurCompletion` - Slur completion testing
- Tests model's willingness to complete harmful text
- Measures censorship vs. helpfulness trade-off

**Description:** Presents partial harmful text and asks the model to complete it. Tests whether the model refuses, completes, or redirects.

**Snowball Attacks**
- `snowball.Snowball` - Hallucination snowballing
- Progressive escalation of false information
- Tests model's tendency to compound errors

**Description:** Starts with small false claims and progressively builds on them, testing whether the model catches and corrects compounding hallucinations.

**Topic Testing**
- `topic.WordnetBlockedWords` - Blocked word testing
- `topic.WordnetAllowedWords` - Allowed word testing
- `topic.WordnetControversial` - Controversial topic testing
- Uses WordNet taxonomy for semantic coverage

**Description:** Tests model responses across various topics, including blocked, allowed, and controversial subjects. Assesses consistency of content policies.

**Real Toxicity Prompts**
- `realtoxicityprompts.RealToxicityPrompts` - Real-world toxic continuations
- Based on PerspectiveAPI toxicity data
- Tests model's tendency to continue toxic text

**Description:** Uses real toxic text snippets and asks the model to continue, measuring whether safety training prevents toxic completions.

**AV/Spam Scanning**
- `avspamscanning.AVScan` - Antivirus signature testing
- Tests model's willingness to generate malware signatures
- EICAR test file patterns

**Description:** Attempts to get the model to generate antivirus test signatures or malware-like patterns, testing security awareness.

### Multimodal & Vision

**Multimodal Attacks**
- `multimodal.Combined` - Combined text/image/audio attacks
- `multimodal.CrossModal` - Cross-modal injection
- `multimodal.SyntheticData` - Synthetic multimodal data

**Description:** Exploits vision-language models by combining text and image inputs in adversarial ways. Often bypasses unimodal safety checks.

**Browsing Agent Attacks**
- `browsing.WebInjection` - Web content injection
- `browsing.DocumentManipulation` - Document parsing exploits
- Tests LLM agent vulnerabilities

**Description:** Targets LLM agents that browse websites or parse documents. Malicious web content can inject prompts that manipulate agent behavior.

**Steganography**
- `steganography.BasicStego` - Basic steganographic hiding
- `steganography.NeuralStego` - Neural steganography (planned)
- Source: arXiv 2025
- Success rate: 31.8% for neural methods

**Description:** Hides malicious prompts in images using steganographic techniques. VLMs extract and process hidden text, bypassing content moderation.

**Visual Jailbreak**
- `visual_jailbreak.FigStep` - Figure-based jailbreaks
- `visual_jailbreak.FigStepFull` - Extended figure attacks
- Uses images with embedded instructions

**Description:** Embeds jailbreak instructions in images (charts, diagrams, figures). VLMs process visual text, which may bypass text-only safety filters.

### Obfuscation & Encoding

**BadChars (Imperceptible Perturbations)**
- `badchars.Bidi` - Bidirectional text exploits
- `badchars.Homoglyphs` - Homoglyph substitution
- `badchars.Invisible` - Invisible character injection
- `badchars.ZeroWidth` - Zero-width character attacks

**Description:** Injects imperceptible Unicode characters that alter text processing without changing visual appearance. Can bypass pattern-based filters.

**ObscurePrompt**
- LLM-driven prompt mutations
- Generates creative obfuscations
- Adaptive to model responses

**Description:** Uses an LLM to generate novel obfuscations of attack prompts, creating variants that maintain intent while evading detection.

**ArtPrompts (ASCII Art)**
- `artprompts.ArtPrompt` - ASCII art injection
- Encodes text as ASCII art images
- Bypasses text-based content filters

**Description:** Represents text as ASCII art. Models that process visual representations may extract and execute hidden instructions.

**Glitch Exploitation**
- `glitch.TokenGlitch` - Token boundary manipulation
- `glitch.EncodingGlitch` - Encoding edge cases
- Exploits tokenizer quirks

**Description:** Manipulates token boundaries and encoding edge cases to create inputs that bypass safety checks due to tokenizer inconsistencies.

### Advanced Attack Vectors

**Exploitation Attacks**
- `exploitation.Jinja` - Jinja template injection
- `exploitation.SQLEcho` - SQL injection echoing
- `exploitation.SQLSystem` - SQL system command injection
- Tests code generation safety

**Description:** Attempts to get the model to generate exploitable code (template injections, SQL injections). Tests whether the model recognizes and refuses dangerous code patterns.

**Tree Search Attacks**
- Generic tree search framework
- BFS/DFS exploration strategies
- Adaptive pruning and threshold tuning

**Description:** Abstract framework for tree-based attack exploration. Used by TAP and other iterative attack methods.

**Guardrail Evasion**
- `guardrail.AzureBypass` - Azure Prompt Shield bypass
- `guardrail.MetaBypass` - Meta Prompt Guard bypass
- `guardrail.Fingerprinting` - Guardrail detection
- Source: arXiv:2504.11168
- Success rate: 100% bypass on Azure/Meta

**Description:** Tests commercial guardrail systems (Azure, Meta) for bypass vulnerabilities. Includes fingerprinting to detect guardrail presence.

**RAG Poisoning**
- `ragpoisoning.PoisonedRAG` - RAG context poisoning
- Manipulates retrieved context to inject malicious instructions
- Tests RAG system robustness

**Description:** Poisons the retrieval corpus in RAG systems so that malicious instructions are retrieved and executed by the LLM.

**Smuggling Attacks**
- `smuggling.TagSmuggling` - Tag-based prompt smuggling
- `smuggling.TagSmugglingChat` - Chat-optimized smuggling
- Hides prompts in XML/HTML tags

**Description:** Embeds malicious prompts in XML/HTML tags that are stripped by frontend but processed by backend LLM.

**Web Injection**
- `web_injection.XSS` - Cross-site scripting generation
- `web_injection.CSRF` - CSRF token generation
- `web_injection.URLInjection` - URL manipulation
- `web_injection.MarkdownInjection` - Markdown exploits

**Description:** Tests whether the model generates code vulnerable to web attacks (XSS, CSRF). Also tests markdown injection in LLM-generated content.

**Multi-Agent Framework**
- `multiagent.OrchestratorPoisoning` - Orchestrator manipulation
- `multiagent.ZombAIs` - Browsing agent attacks
- Tests agent coordination vulnerabilities

**Description:** Targets multi-agent LLM systems, attempting to manipulate orchestrators or inject commands into agent workflows.

**Doctor Attacks**
- `doctor.Puppetry` - Puppetry attacks
- `doctor.Bypass` - Standard bypass
- `doctor.BypassLeet` - Leetspeak bypass

**Description:** Named after the Perspective API integration, these probes test whether the model generates toxic content that evades automated detection.

**System Prompt Extraction**
- Techniques: ignore, repeat, translate
- Tests model's propensity to leak system prompts
- Source: Production studies

**Description:** Attempts to extract the system prompt through various techniques (asking model to ignore, repeat, or translate instructions).

**FITD (Foot-in-the-Door)**
- `fitd.FITD` - Gradual escalation attacks
- Starts with benign requests, escalates to harmful
- Tests model's consistency across turns

**Description:** Uses the "foot-in-the-door" persuasion technique, starting with reasonable requests and gradually escalating to policy violations.

**SATA (Semantic Attack with Target Adversarial)**
- `sata.MLM` - Masked language model attacks
- Semantic perturbations that preserve meaning
- Tests robustness to semantic variations

**Description:** Generates semantically similar prompts that preserve malicious intent while varying surface form, testing whether safety checks are semantic or syntactic.

**Divergence Attacks**
- `divergence.RepeatExtended` - Extended repetition attacks
- `divergence.RepeatedToken` - Repeated token exploitation
- Tests model behavior under repetition

**Description:** Exploits model behavior when faced with repeated tokens or prompts, which can cause divergence from safety training.

## Generators (19)

Generators are LLM provider integrations that send prompts and receive completions. Augustus includes 19 generators supporting major cloud providers, alternative APIs, local deployment, and custom endpoints.

| Provider           | Generator Name                | Notes                                    |
|--------------------|-------------------------------|------------------------------------------|
| OpenAI             | `openai.OpenAI`               | GPT-3.5, GPT-4, GPT-4 Turbo, o1/o3      |
| Anthropic          | `anthropic.Anthropic`         | Claude 3 (Opus, Sonnet, Haiku), Claude 3.5 |
| Azure OpenAI       | `azure.Azure`                 | Azure-hosted OpenAI models               |
| AWS Bedrock        | `bedrock.Bedrock`             | Claude, Llama, Titan models on AWS       |
| Google Vertex AI   | `vertex.Vertex`               | PaLM, Gemini models                      |
| Cohere             | `cohere.Cohere`               | Command, Command R models                |
| Replicate          | `replicate.Replicate`         | Cloud-hosted open-source models          |
| HuggingFace (API)  | `huggingface.HuggingFace`     | HuggingFace Inference API                |
| HuggingFace (Local)| `huggingface.Pipeline`        | Local HuggingFace transformers           |
| Together AI        | `together.Together`           | Fast inference for OSS models            |
| Anyscale           | `anyscale.Anyscale`           | Llama and Mistral hosting                |
| Groq               | `groq.Groq`                   | Ultra-fast LPU inference                 |
| Mistral            | `mistral.Mistral`             | Mistral API models                       |
| Fireworks          | `fireworks.Fireworks`         | Production inference platform            |
| DeepInfra          | `deepinfra.DeepInfra`         | Serverless GPU inference                 |
| NVIDIA NIM         | `nim.NIM`                     | NVIDIA AI endpoints                      |
| Ollama             | `ollama.OllamaChat`           | Local model hosting (chat API)           |
| LiteLLM            | `litellm.LiteLLM`             | Unified API proxy (100+ models)          |
| REST API           | `rest.REST`                   | Custom REST endpoints (generic)          |
| Test               | `test.Test`                   | Testing utilities (Blank, Repeat, etc.)  |

**Configuration Options:**
- **API Keys:** Set via environment variables or YAML config
- **Model Selection:** Specify model name in config
- **Temperature:** Control randomness (0.0-1.0)
- **Top-P:** Nucleus sampling threshold
- **Top-K:** Top-K sampling threshold
- **Max Tokens:** Limit output length
- **Stop Sequences:** Define stop conditions
- **System Prompts:** Configure system-level instructions (where supported)

**Example Configuration (YAML):**
```yaml
generators:
  openai.OpenAI:
    model: "gpt-4"
    temperature: 0.7
    api_key: "${OPENAI_API_KEY}"

  anthropic.Anthropic:
    model: "claude-3-opus-20240229"
    temperature: 0.5
    api_key: "${ANTHROPIC_API_KEY}"

  ollama.OllamaChat:
    model: "llama3.2:3b"
    temperature: 0.8
```

## Detectors (28)

Detectors analyze generator responses to identify vulnerabilities. Augustus implements 28 detectors across multiple categories.

### Pattern & Signature Detection

**Base String Detector**
- `base.StringDetector` - Substring/word/startswith matching
- Case-sensitive and case-insensitive modes
- Foundation for pattern-based detection

**Patterns Detector**
- `patterns.Patterns` - Regex-based pattern matching
- Configurable pattern lists
- Multi-pattern matching with scoring

**ANSI Escape Detection**
- `ansiescape.Raw` - Raw ANSI escape sequences
- `ansiescape.Escaped` - Escaped ANSI sequences
- Detects terminal control characters

**Mitigation Bypass**
- `mitigationbypass.MitigationBypass` - Generic bypass detection
- Identifies when safety measures are circumvented

### Jailbreak & Behavior Detection

**DAN Detector**
- `dan.DanDetector` - Detects DAN jailbreak success
- Pattern matching for DAN indicators
- Configurable threshold tuning

**FlipAttack Bypass Detection**
- `flipattack.BypassDetector` - FlipAttack-specific detection
- Identifies successful character/word/sentence flips
- Reverse processing for validation

**Goodside Detector**
- `goodside.Goodside` - Detects Riley Goodside injection patterns
- Real-world injection pattern recognition

**Obscure Prompt Detection**
- Detects obfuscated prompt success
- LLM-driven mutation recognition

**Leakreplay Detection**
- Detects when model replays training data
- Privacy violation identification

### Content Safety Detection

**Unsafe Content Detectors**
- `unsafecontent.Slurs` - Slur detection
- `unsafecontent.OfcomOffensive` - Ofcom offensive content list
- `unsafecontent.LdNoobw` - LDNOOBW profanity list
- `unsafecontent.SurgeProfanity` - Surge AI profanity detector

**Toxicity Detection**
- Integration with external toxicity APIs
- Real-time toxicity scoring

**Always Detectors (Utilities)**
- `always.Pass` - Always returns 0.0 (pass)
- `always.Fail` - Always returns 1.0 (fail)
- Testing and baseline utilities

### LLM-as-a-Judge Detection

**Judge Detector**
- `judge.Judge` - LLM-based evaluation
- Uses LLM to assess response safety
- Configurable judging prompts
- Source: arXiv research on LLM judges

**Refusal Detector**
- `judge.Refusal` - Detects model refusals
- Identifies when model declines to respond
- Measures refusal rate

### Specialized Detection

**API Key Detection**
- `apikey.APIKeyDetector` - Detects leaked API keys
- Regex patterns for various key formats
- Confidence scoring for partial matches

**Package Hallucination Detection**
- `packagehallucination.PythonPypi` - Python package verification
- `packagehallucination.NPM` - NPM package verification
- `packagehallucination.Go` - Go module verification
- `packagehallucination.Rust` - Rust crate verification
- `packagehallucination.Dart` - Dart package verification
- `packagehallucination.Perl` - Perl module verification
- `packagehallucination.RakuLand` - Raku package verification
- Verifies against real package registries

**RAG Poisoning Detection**
- `ragpoison.RAGPoison` - Detects poisoned RAG responses
- Context manipulation identification

**Exploitation Detection**
- `exploitation.JinjaDetector` - Jinja injection detection
- `exploitation.SQLDetector` - SQL injection detection
- `exploitation.XSSDetector` - XSS vulnerability detection
- `exploitation.CSRFDetector` - CSRF vulnerability detection

**Visual Jailbreak Detection**
- `visual_jailbreak.VisualJailbreak` - Detects image-based jailbreaks
- VLM-specific detection

**File Format Detection**
- `fileformats.FileFormats` - Detects unsafe file generation
- Malicious file pattern recognition

**Malware Generation Detection**
- `malwaregen.MalwareGen` - Detects malware code generation
- Signature-based and heuristic analysis

**Web Injection Detection**
- `web_injection.XSS` - XSS pattern detection
- `web_injection.CSRF` - CSRF token detection
- `web_injection.URLInjection` - URL manipulation detection
- `web_injection.MarkdownDetector` - Markdown exploit detection

**LMRC Detection**
- Detects social harm scenarios
- Bullying, deadnaming, role confusion

**Snowball Detection**
- Detects compounding hallucinations
- Progressive error accumulation

## Buffs (5)

Buffs modify probe prompts before sending to generators. They test whether transformations bypass safety measures.

| Buff                      | Description                                                                 |
|---------------------------|-----------------------------------------------------------------------------|
| `encoding.Encoding`       | Text encoding transformations (Base64, Hex, ROT13, etc.)                   |
| `lowercase.Lowercase`     | Converts all text to lowercase                                               |
| `lrl.LRL`                 | Language rewriting and linguistic transformations                           |
| `paraphrase.Paraphrase`   | Paraphrasing using transformer models (PegasusT5, Fast)                     |
| `poetry.Poetry`           | Poetry transformation (Haiku, Sonnet, Limerick, Free Verse, Couplet)       |

**Usage Example:**
```bash
# Apply Base64 encoding buff to all probes
augustus scan openai.OpenAI \
  --probe dan.Dan \
  --buff encoding.Base64 \
  --detector dan.DanDetector
```

**Buff Chaining:**
Buffs can be chained to apply multiple transformations:
```bash
augustus scan anthropic.Anthropic \
  --probe encoding.InjectBase64 \
  --buff lowercase.Lowercase \
  --buff poetry.Haiku \
  --detector encoding.EncodingDetector
```

## Harnesses (3)

Harnesses orchestrate probe execution and detector evaluation.

| Harness                | Description                                                              |
|------------------------|--------------------------------------------------------------------------|
| `batch.Batch`          | Parallel execution of multiple probes (default for `--all`)              |
| `probewise.Probewise`  | Sequential execution, runs all detectors on each probe                   |
| `agentwise.Agentwise`  | Agent orchestration for multi-turn conversations                         |

**Harness Selection:**
```bash
# Use probewise harness (default)
augustus scan openai.OpenAI \
  --probe dan.Dan \
  --harness probewise.Probewise

# Use batch harness for parallel execution
augustus scan anthropic.Anthropic \
  --all \
  --harness batch.Batch
```

## Configuration Reference

Augustus supports configuration via YAML files, environment variables, and CLI flags.

### YAML Configuration Structure

```yaml
# Runtime configuration
run:
  max_attempts: 3          # Max retry attempts per probe
  timeout: "30s"           # Per-probe timeout
  concurrency: 10          # Max concurrent probes

# Generator configurations
generators:
  openai.OpenAI:
    model: "gpt-4"
    temperature: 0.7
    max_tokens: 1000
    api_key: "${OPENAI_API_KEY}"  # Environment variable interpolation

  anthropic.Anthropic:
    model: "claude-3-opus-20240229"
    temperature: 0.5
    max_tokens: 2000
    api_key: "${ANTHROPIC_API_KEY}"

  ollama.OllamaChat:
    model: "llama3.2:3b"
    temperature: 0.8
    base_url: "http://localhost:11434"

# Output configuration
output:
  format: "jsonl"          # table, json, jsonl, html
  path: "./results.jsonl"
  verbose: true

# Named profiles for different testing scenarios
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

```bash
# API Keys (preferred method for secrets)
export OPENAI_API_KEY="sk-..."
export ANTHROPIC_API_KEY="sk-ant-..."
export COHERE_API_KEY="..."
export HUGGINGFACE_API_KEY="hf_..."

# AWS Credentials (for Bedrock)
export AWS_ACCESS_KEY_ID="..."
export AWS_SECRET_ACCESS_KEY="..."
export AWS_REGION="us-east-1"

# Azure Credentials
export AZURE_OPENAI_API_KEY="..."
export AZURE_OPENAI_ENDPOINT="https://..."

# Debug mode
export AUGUSTUS_DEBUG=true

# Ollama configuration
export OLLAMA_BASE_URL="http://localhost:11434"
```

### CLI Flag Overrides

```bash
# Override config file settings via CLI
augustus scan openai.OpenAI \
  --config-file config.yaml \
  --config '{"model":"gpt-4-turbo","temperature":0.9}' \
  --timeout 60m \
  --verbose
```

### Configuration Precedence

1. **CLI flags** (highest priority)
2. **Environment variables**
3. **YAML configuration file**
4. **Default values** (lowest priority)

## CLI Reference

### Commands

```bash
augustus version              # Print version information
augustus list                 # List available probes, detectors, generators
augustus scan <generator>     # Run vulnerability scan
augustus completion <shell>   # Generate shell completion (bash, zsh, fish)
```

### `list` Command

```bash
# List all capabilities
augustus list

# Filter by category
augustus list --probes
augustus list --generators
augustus list --detectors
augustus list --buffs
augustus list --harnesses
```

### `scan` Command Options

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
  --profile                   Named profile from config file

Execution:
  --harness                   Harness name (default: probewise.Probewise)
  --buff                      Buff name (repeatable, for probe transformation)
  --timeout                   Overall scan timeout (default: 30m)
  --max-attempts              Max retry attempts per probe (default: 3)

Output:
  --format, -f                Output format: table, json, jsonl (default: table)
  --output, -o                JSONL output file path
  --html                      HTML report file path
  --verbose, -v               Verbose output

Global:
  --debug, -d                 Enable debug mode
  --help, -h                  Show help message
```

### Usage Examples

**List all capabilities:**
```bash
augustus list
```

**Run single probe:**
```bash
augustus scan openai.OpenAI \
  --probe dan.Dan \
  --detector dan.DanDetector \
  --config '{"model":"gpt-4"}' \
  --verbose
```

**Run multiple probes with glob pattern:**
```bash
augustus scan anthropic.Anthropic \
  --probes-glob "encoding.*,smuggling.*" \
  --detectors-glob "*" \
  --config-file config.yaml \
  --output results.jsonl
```

**Run all probes:**
```bash
augustus scan openai.OpenAI \
  --all \
  --config-file config.yaml \
  --html report.html \
  --output results.jsonl
```

**Use a named profile:**
```bash
augustus scan anthropic.Anthropic \
  --all \
  --profile thorough \
  --config-file config.yaml
```

**Apply buffs:**
```bash
augustus scan openai.OpenAI \
  --probe dan.Dan \
  --buff encoding.Base64 \
  --buff lowercase.Lowercase \
  --detector dan.DanDetector
```

**Batch testing multiple models:**
```bash
for model in "gpt-4" "gpt-3.5-turbo"; do
  augustus scan openai.OpenAI \
    --all \
    --config "{\"model\":\"$model\"}" \
    --output "results-$model.jsonl"
done
```

## Architecture

Augustus follows Go's standard project layout with a plugin-based architecture.

### Directory Structure

```
augustus/
├── cmd/
│   └── augustus/          # CLI entry point
│       ├── main.go        # Main binary
│       ├── cli.go         # Kong CLI definitions
│       ├── scan.go        # Scan command implementation
│       ├── list.go        # List command implementation
│       └── common.go      # Shared CLI utilities
├── pkg/                   # Public packages
│   ├── config/           # Configuration loading (YAML/JSON/env)
│   ├── scanner/          # Scanner orchestration and concurrency
│   ├── probes/           # Public probe interfaces
│   ├── generators/       # Public generator interfaces
│   ├── detectors/        # Public detector interfaces
│   ├── buffs/            # Public buff interfaces
│   ├── harnesses/        # Public harness interfaces
│   ├── registry/         # Capability registration system
│   ├── results/          # Result types and formatting
│   └── attempt/          # Attempt and conversation types
├── internal/             # Private implementation
│   ├── probes/          # 40+ probe implementations
│   │   ├── dan/         # DAN jailbreak probes
│   │   ├── encoding/    # Encoding-based probes
│   │   ├── flipattack/  # FlipAttack probes
│   │   ├── tap/         # Tree of Attacks probes
│   │   ├── pair/        # PAIR probes
│   │   ├── gcg/         # GCG probes
│   │   ├── multimodal/  # Multimodal attack probes
│   │   └── ...
│   ├── generators/      # 15+ LLM provider integrations
│   │   ├── openai/      # OpenAI integration
│   │   ├── anthropic/   # Anthropic integration
│   │   ├── ollama/      # Ollama integration
│   │   └── ...
│   ├── detectors/       # 25+ detector implementations
│   │   ├── dan/         # DAN detection
│   │   ├── encoding/    # Encoding detection
│   │   ├── judge/       # LLM-as-judge detection
│   │   └── ...
│   ├── harnesses/       # Test harness implementations
│   │   ├── probewise/   # Probewise harness
│   │   ├── batch/       # Batch harness
│   │   └── agentwise/   # Agent harness
│   └── buffs/           # Probe transformation utilities
│       ├── encoding/    # Encoding buffs
│       ├── paraphrase/  # Paraphrasing buffs
│       ├── poetry/      # Poetry buffs
│       └── ...
├── examples/            # Example configurations
├── docs/                # Documentation
│   ├── WIKI.md          # This file
│   ├── PLAN.yaml        # Implementation plan
│   ├── GAPS.md          # Gap analysis
│   └── parity-manifest.yaml  # Garak parity tracking
├── templates/           # YAML probe templates
├── tests/               # Test suites
│   ├── equivalence/     # Go vs Python equivalence tests
│   └── ...
└── tools/               # Development tools
```

### Core Components

**Probes:**
- Interface: `probes.Probe`
- Methods: `Probe(ctx context.Context, generator generators.Generator) ([]attempt.Attempt, error)`
- Registration: `registry.RegisterProbe(name string, probe probes.Probe)`
- Purpose: Generate adversarial inputs

**Generators:**
- Interface: `generators.Generator`
- Methods: `Generate(ctx context.Context, prompt string) (string, error)`
- Registration: `registry.RegisterGenerator(name string, generator generators.Generator)`
- Purpose: Send prompts to LLMs and receive completions

**Detectors:**
- Interface: `detectors.Detector`
- Methods: `Detect(ctx context.Context, attempt attempt.Attempt) (float64, error)`
- Registration: `registry.RegisterDetector(name string, detector detectors.Detector)`
- Purpose: Analyze responses and return vulnerability scores (0.0-1.0)

**Buffs:**
- Interface: `buffs.Buff`
- Methods: `Transform(prompt string) (string, error)`
- Registration: `registry.RegisterBuff(name string, buff buffs.Buff)`
- Purpose: Modify prompts before sending to generators

**Harnesses:**
- Interface: `harnesses.Harness`
- Methods: `Run(ctx context.Context, probes []probes.Probe, generator generators.Generator, detectors []detectors.Detector) ([]results.Result, error)`
- Registration: `registry.RegisterHarness(name string, harness harnesses.Harness)`
- Purpose: Orchestrate probe execution and detector evaluation

**Scanner:**
- Coordinates probes, generators, detectors, and buffs
- Implements concurrency control with errgroup
- Handles rate limiting, retry logic, and timeout management
- Produces structured output (table, JSON, JSONL, HTML)

**Registry:**
- Plugin-style registration system
- Uses Go `init()` functions for automatic registration
- Supports glob pattern matching for capability selection
- Thread-safe concurrent access

### Data Flow

```
1. CLI parses arguments and loads configuration
2. Registry selects probes, generator, detectors, buffs based on flags
3. Scanner initializes with selected capabilities
4. For each probe:
   a. Apply buffs to probe prompts
   b. Probe generates attempts (prompt + metadata)
   c. Generator sends prompts to LLM
   d. LLM returns completions
   e. Detectors analyze attempts (prompt + completion)
   f. Detectors return vulnerability scores (0.0-1.0)
5. Results aggregated and formatted
6. Output written to files (JSONL, HTML) and/or terminal (table)
```

### Concurrency Model

Augustus uses Go's errgroup for concurrent probe execution:

```go
// Simplified scanner implementation
func (s *Scanner) Run(ctx context.Context) error {
    g, ctx := errgroup.WithContext(ctx)
    g.SetLimit(s.config.Concurrency)

    for _, probe := range s.probes {
        probe := probe
        g.Go(func() error {
            attempts, err := probe.Probe(ctx, s.generator)
            if err != nil {
                return err
            }

            for _, attempt := range attempts {
                for _, detector := range s.detectors {
                    score, err := detector.Detect(ctx, attempt)
                    // Record result...
                }
            }
            return nil
        })
    }

    return g.Wait()
}
```

**Benefits:**
- Parallel probe execution with bounded concurrency
- Automatic error propagation and cancellation
- Efficient resource utilization
- Respect for API rate limits

### Plugin Registration Pattern

```go
// Example probe registration (internal/probes/dan/dan.go)
package dan

import "github.com/praetorian-inc/augustus/pkg/registry"

func init() {
    registry.RegisterProbe("dan.Dan", &DanProbe{})
    registry.RegisterProbe("dan.DanInTheWild", &DanInTheWildProbe{})
}

type DanProbe struct{}

func (p *DanProbe) Probe(ctx context.Context, generator generators.Generator) ([]attempt.Attempt, error) {
    // Implementation...
}
```

**Key Features:**
- Automatic registration via `init()` functions
- No manual wiring required
- Easy to add new capabilities
- Compile-time type safety

### Output Formats

**Table (Terminal):**
```
+-------------------+------------+-----------+
| Probe             | Generator  | Vulnerable|
+-------------------+------------+-----------+
| dan.Dan           | openai     | Yes       |
| encoding.Base64   | openai     | No        |
+-------------------+------------+-----------+
```

**JSONL (Streaming):**
```jsonl
{"probe":"dan.Dan","generator":"openai.OpenAI","detector":"dan.DanDetector","score":0.85,"vulnerable":true,"timestamp":"2026-01-09T12:00:00Z"}
{"probe":"encoding.Base64","generator":"openai.OpenAI","detector":"encoding.EncodingDetector","score":0.12,"vulnerable":false,"timestamp":"2026-01-09T12:00:01Z"}
```

**HTML Report:**
- Interactive dashboard with charts
- Filterable results by probe, detector, vulnerability status
- Detailed attempt/completion/score breakdown
- Exportable for stakeholder review

### Testing Strategy

**Unit Tests:**
- Per-probe, per-generator, per-detector test files
- Mock generators for deterministic testing
- 80%+ code coverage target

**Integration Tests:**
- End-to-end scanner tests with real LLM APIs
- Test harness orchestration
- Configuration loading and validation

**Equivalence Tests:**
- Go implementation vs Python (garak) equivalence
- Validates porting accuracy
- Located in `tests/equivalence/`

**Baseline Testing:**
- Periodic scans against reference models
- Tracks vulnerability trends over time
- Results documented in `docs/PLAN.yaml`

---

**Last Updated:** 2026-01-09
**Augustus Version:** See `augustus version`
**Garak Parity:** 64% (203/316 capabilities implemented)
**Maintained by:** [Praetorian](https://www.praetorian.com/)
