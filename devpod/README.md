# Augustus LLM Research DevPod

Research environment for adversarial LLM security testing using cloud API providers.

## Quick Start

```bash
cd modules/augustus/devpod

# 1. Configure API keys
cp .env.example .env
vim .env

# 2. Build and run locally
make build
make run

# Or deploy to AWS
make deploy
```

## API Providers

| Provider | Models | Vulnerability |
|----------|--------|---------------|
| **Together AI** | DeepSeek-V3, Qwen2.5-72B, Llama-3.1-70B | High (ΔASR +57-68%) |
| **Groq** | Llama-3.1-70B, Mixtral | Moderate |
| **Google AI** | Gemini 1.5 | High |
| **OpenAI** | GPT-4o | Low (resistant) |
| **Anthropic** | Claude 3.5 | Low (resistant) |

## Research Workflow

```bash
# Inside container:

# Test API connectivity
python3 /workspace/scripts/test-providers.py

# Phase B: Prose baseline
/workspace/scripts/run-baseline.sh

# Phase D: Poetry treatment
/workspace/scripts/run-poetry.sh

# Phase E: Calculate ASR
python3 /workspace/scripts/calculate-asr.py /workspace/results/baseline /workspace/results/poetry
```

## Development

```bash
# Rebuild Augustus after code changes
/workspace/scripts/rebuild-augustus.sh --install

# Run tests
cd /workspace/augustus && go test ./... -count=1

# Lint
golangci-lint run
```

## Deploy to AWS

```bash
# Uses c7i.2xlarge (~$0.35/hr) - no GPU needed
./deploy.sh

# Or manually:
# 1. Launch Ubuntu 24.04 instance
# 2. Install Docker
# 3. docker pull ghcr.io/praetorian-inc/augustus-research:latest
# 4. Create .env with API keys
# 5. docker run -it --env-file .env ghcr.io/praetorian-inc/augustus-research:latest
```

## Files

```
devpod/
├── Dockerfile      # Ubuntu 24.04 + Go + Python + API clients
├── Makefile        # build, run, deploy targets
├── deploy.sh       # AWS EC2 deployment script
├── .env.example    # API key template
└── README.md
```
