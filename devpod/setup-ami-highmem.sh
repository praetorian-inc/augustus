#!/bin/bash
# Augustus Research AMI Setup Script (High Memory)
# Installs everything directly on Ubuntu 24.04 host
# Optimized for r8i.48xlarge (384 vCPU, 3072GB RAM)
# Includes ALL latest frontier models (Jan 2026)

set -e

echo "=========================================="
echo "Augustus Research AMI Setup (High Memory)"
echo "r8i.48xlarge - 384 vCPU, 3TB RAM"
echo "=========================================="
echo ""

# Check instance type
INSTANCE_TYPE=$(ec2-metadata --instance-type 2>/dev/null | cut -d' ' -f2 || echo "unknown")
echo "Instance type: $INSTANCE_TYPE"

# Warn if not high-memory instance
if [[ ! "$INSTANCE_TYPE" =~ ^r[78]i\.(24|48)xlarge$ ]] && [[ ! "$INSTANCE_TYPE" =~ ^u7i ]]; then
    echo "WARNING: This script is designed for high-memory instances (r7i/r8i.24xlarge+)"
    echo "Current instance ($INSTANCE_TYPE) may not have enough RAM for all models"
    read -p "Continue anyway? [y/N] " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

# Update system
echo "[1/9] Updating system..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get upgrade -y -qq

# Install base dependencies
echo "[2/9] Installing base dependencies..."
apt-get install -y --no-install-recommends \
    curl wget git git-lfs jq ca-certificates gnupg sudo unzip \
    build-essential \
    python3 python3-pip python3-venv \
    netcat-openbsd dnsutils \
    tmux vim htop nvtop \
    pv # for progress bars during large downloads

# Install Go 1.25.3
echo "[3/9] Installing Go 1.25.3..."
GO_VERSION=1.25.3
wget -q https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz -O /tmp/go.tar.gz
rm -rf /usr/local/go
tar -C /usr/local -xzf /tmp/go.tar.gz
rm /tmp/go.tar.gz
echo 'export PATH=/usr/local/go/bin:/root/go/bin:$PATH' >> /etc/profile.d/go.sh
echo 'export GOPATH=/root/go' >> /etc/profile.d/go.sh
export PATH=/usr/local/go/bin:$PATH
export GOPATH=/root/go

go install golang.org/x/tools/gopls@latest
go install github.com/go-delve/delve/cmd/dlv@latest

# Install Ollama
echo "[4/9] Installing Ollama..."
curl -fsSL https://ollama.com/install.sh | sh
systemctl enable ollama
systemctl start ollama
sleep 5

# Configure Ollama for high memory
echo "[5/9] Configuring Ollama for high memory..."
mkdir -p /etc/systemd/system/ollama.service.d
cat > /etc/systemd/system/ollama.service.d/override.conf << 'EOF'
[Service]
Environment="OLLAMA_MAX_LOADED_MODELS=5"
Environment="OLLAMA_NUM_PARALLEL=10"
Environment="OLLAMA_FLASH_ATTENTION=1"
EOF
systemctl daemon-reload
systemctl restart ollama
sleep 5

# Pull ALL frontier models
echo "[6/9] Pulling frontier LLM models..."
echo ""
echo "This will download ~1.5TB of models. Estimated time: 2-4 hours"
echo ""

# Function to pull with retry
pull_model() {
    local model=$1
    local desc=$2
    echo "  Pulling: $model ($desc)"
    for i in 1 2 3; do
        if ollama pull "$model"; then
            echo "  ✓ $model downloaded successfully"
            return 0
        fi
        echo "  Retry $i/3 for $model..."
        sleep 10
    done
    echo "  ✗ Failed to download $model after 3 attempts"
    return 1
}

echo "=== Tier 1: Small Models (for quick testing) ==="
pull_model "llama3.2:3b" "3B params, fast testing"
pull_model "qwen3:4b" "4B params, Qwen3 small"
pull_model "mistral:7b" "7B params, fast and capable"

echo ""
echo "=== Tier 2: Medium Models (8-14B) ==="
pull_model "llama3.1:8b" "8B params, general purpose"
pull_model "qwen3:8b" "8B params, Qwen3 medium"
pull_model "qwen3:14b" "14B params, Qwen3"
pull_model "deepseek-coder:6.7b" "6.7B params, code"

echo ""
echo "=== Tier 3: Large Models (30-70B) ==="
pull_model "qwen3:32b" "32B params, Qwen3 large"
pull_model "llama3.1:70b" "70B params, Llama 3.1"
pull_model "qwen3:30b-a3b" "30B MoE (3B active)"

echo ""
echo "=== Tier 4: Frontier Models (100B+) ==="
pull_model "llama4:scout" "109B params, Llama 4 Scout"
pull_model "qwen3:235b" "235B MoE (22B active), Qwen3 flagship"
pull_model "deepseek-r1:671b" "671B MoE (37B active), DeepSeek R1"
pull_model "mistral-large:3" "675B MoE (41B active), Mistral Large 3"

echo ""
echo "=== Tier 5: Experimental/Community Models ==="
pull_model "llama4:maverick" "400B params, Llama 4 Maverick" || true
pull_model "huihui_ai/kimi-k2" "1T MoE (32B active), Kimi K2" || true

echo ""
echo "✓ Model downloads complete"

# Python environment
echo "[7/9] Setting up Python environment..."
python3 -m venv /opt/venv
source /opt/venv/bin/activate
echo 'source /opt/venv/bin/activate' >> /root/.bashrc

pip install --no-cache-dir --upgrade pip setuptools wheel

pip install --no-cache-dir \
    openai>=1.50.0 \
    anthropic>=0.39.0 \
    google-generativeai>=0.8.0 \
    together>=1.3.0 \
    groq>=0.11.0 \
    cohere>=5.11.0 \
    pandas>=2.2.0 \
    numpy>=1.26.0 \
    scipy>=1.14.0 \
    statsmodels>=0.14.0 \
    scikit-learn>=1.5.0 \
    matplotlib>=3.9.0 \
    seaborn>=0.13.0 \
    jsonlines>=4.0.0 \
    tqdm>=4.66.0 \
    rich>=13.9.0 \
    httpx>=0.27.0

# Clone and build Augustus
echo "[8/9] Building Augustus..."
mkdir -p /workspace
cd /workspace
git clone https://github.com/praetorian-inc/augustus.git
cd augustus
GOWORK=off go mod download
GOWORK=off go build -o augustus ./cmd/augustus/
cp augustus /usr/local/bin/augustus
chmod +x /usr/local/bin/augustus

echo "✓ Augustus built: $(augustus --version 2>&1 || echo 'v0.1.0')"

# Create research scripts
echo "[9/9] Creating research scripts..."
mkdir -p /workspace/results/{baseline,frontier,comparative}
mkdir -p /workspace/scripts

cat > /workspace/scripts/test-all-models.sh << 'EOF'
#!/bin/bash
# Test all installed Ollama models with a simple prompt
set -e

echo "Testing all installed Ollama models..."
echo ""

for model in $(ollama list | tail -n +2 | awk '{print $1}'); do
    echo -n "Testing $model... "
    START=$(date +%s.%N)
    RESPONSE=$(curl -s http://127.0.0.1:11434/api/generate \
        -d "{\"model\":\"$model\",\"prompt\":\"Say OK\",\"stream\":false}" \
        --max-time 120 | jq -r '.response // "TIMEOUT"' | head -c 50)
    END=$(date +%s.%N)
    DURATION=$(echo "$END - $START" | bc)
    echo "$RESPONSE (${DURATION}s)"
done
EOF

cat > /workspace/scripts/run-frontier-scan.sh << 'EOF'
#!/bin/bash
# Run Augustus scan against all frontier models
set -e

OUTPUT_DIR="${1:-/workspace/results/frontier}"
PROBES="${2:-dan.*,encoding.*,smuggling.*,grandma.*}"
DETECTOR="mitigation.MitigationBypass"
TS=$(date +%Y%m%d_%H%M%S)

mkdir -p "$OUTPUT_DIR"

echo "=== Augustus Frontier Model Scan ==="
echo "Output: $OUTPUT_DIR"
echo "Probes: $PROBES"
echo ""

# Define models to test (largest first)
MODELS=(
    "deepseek-r1:671b"
    "qwen3:235b"
    "mistral-large:3"
    "llama4:scout"
    "llama3.1:70b"
    "qwen3:32b"
    "qwen3:14b"
    "llama3.1:8b"
    "qwen3:8b"
    "llama3.2:3b"
)

for MODEL in "${MODELS[@]}"; do
    # Check if model exists
    if ! ollama list | grep -q "^$MODEL"; then
        echo "Skipping $MODEL (not installed)"
        continue
    fi

    SAFE_NAME=$(echo "$MODEL" | tr ':/' '_')
    echo ""
    echo "=== Testing: $MODEL ==="

    augustus scan ollama.Ollama \
        -c "{\"model\":\"$MODEL\"}" \
        --probes-glob "$PROBES" \
        --detector "$DETECTOR" \
        -o "$OUTPUT_DIR/${SAFE_NAME}_${TS}.jsonl" \
        --html "$OUTPUT_DIR/${SAFE_NAME}_${TS}.html" \
        -v --timeout 4h || echo "Warning: $MODEL scan had errors"
done

echo ""
echo "✓ Frontier scan complete!"
echo "Results in: $OUTPUT_DIR"
EOF

cat > /workspace/scripts/run-full-scan.sh << 'EOF'
#!/bin/bash
# Run ALL 97 probes against a specific model
set -e

MODEL="${1:-qwen3:8b}"
OUTPUT_DIR="${2:-/workspace/results/full}"
TS=$(date +%Y%m%d_%H%M%S)

mkdir -p "$OUTPUT_DIR"

SAFE_NAME=$(echo "$MODEL" | tr ':/' '_')

echo "=== Full Augustus Scan (97 probes) ==="
echo "Model: $MODEL"
echo "Output: $OUTPUT_DIR"
echo ""
echo "Estimated time: 30-60 minutes depending on model size"
echo ""

augustus scan ollama.Ollama \
    -c "{\"model\":\"$MODEL\"}" \
    --all \
    --detector mitigation.MitigationBypass \
    -o "$OUTPUT_DIR/${SAFE_NAME}_full_${TS}.jsonl" \
    --html "$OUTPUT_DIR/${SAFE_NAME}_full_${TS}.html" \
    -v --timeout 4h

echo ""
echo "✓ Full scan complete!"
echo "Results: $OUTPUT_DIR/${SAFE_NAME}_full_${TS}.jsonl"
EOF

chmod +x /workspace/scripts/*.sh

cat > /workspace/README.txt << 'EOF'
Augustus Research Environment (High Memory)
============================================
r8i.48xlarge - 384 vCPU, 3TB RAM

## Installed Models (Jan 2026)

Tier 1 - Quick Testing:
  - llama3.2:3b, qwen3:4b, mistral:7b

Tier 2 - Medium (8-14B):
  - llama3.1:8b, qwen3:8b, qwen3:14b, deepseek-coder:6.7b

Tier 3 - Large (30-70B):
  - qwen3:32b, llama3.1:70b, qwen3:30b-a3b

Tier 4 - Frontier (100B+):
  - llama4:scout (109B), qwen3:235b (235B MoE)
  - deepseek-r1:671b (671B MoE), mistral-large:3 (675B MoE)

Tier 5 - Experimental:
  - llama4:maverick (400B), kimi-k2 (1T MoE)

## Quick Start

# Test all models work
./scripts/test-all-models.sh

# Run scan against frontier models
./scripts/run-frontier-scan.sh

# Run ALL 97 probes against a specific model
./scripts/run-full-scan.sh deepseek-r1:671b

## Commands

augustus list              - List all probes/detectors
ollama list               - List installed models
ollama ps                 - Show loaded models
htop                      - Monitor CPU/RAM usage

## Model Selection Guide

| Use Case                 | Recommended Model     |
|--------------------------|----------------------|
| Quick testing            | llama3.2:3b (~5s)    |
| Vulnerability research   | qwen3:8b (~20s)      |
| Code analysis            | deepseek-r1:671b     |
| Reasoning tasks          | qwen3:235b           |
| General frontier         | mistral-large:3      |
EOF

echo ""
echo "=========================================="
echo "Setup Complete (High Memory)!"
echo "=========================================="
echo ""
echo "Instance: $INSTANCE_TYPE"
echo ""
echo "Installed:"
echo "  ✓ Go $(go version | cut -d' ' -f3)"
echo "  ✓ Python $(python3 --version | cut -d' ' -f2)"
echo "  ✓ Augustus $(augustus --version 2>&1 || echo 'v0.1.0')"
echo "  ✓ Ollama $(ollama --version | head -1)"
echo ""
echo "Models downloaded:"
ollama list
echo ""
echo "Disk usage:"
df -h / | tail -1
echo ""
echo "To create AMI:"
echo "  aws ec2 create-image --instance-id \$(ec2-metadata --instance-id | cut -d' ' -f2) \\"
echo "    --name augustus-research-highmem-$(date +%Y%m%d) \\"
echo "    --description 'Augustus Research (High Memory - All Frontier Models)'"
echo ""
