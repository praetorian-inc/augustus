#!/bin/bash
# Augustus Research AMI Setup Script
# Installs everything directly on Ubuntu 24.04 host (no Docker)
# Run this on a fresh g5.2xlarge instance, then create AMI from it

set -e

echo "=========================================="
echo "Augustus Research AMI Setup"
echo "=========================================="
echo ""

# System info
echo "Instance type: $(ec2-metadata --instance-type | cut -d: -f2)"
echo "GPU: $(lspci | grep -i nvidia || echo 'No GPU detected')"
echo ""

# Update system
echo "[1/10] Updating system..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get upgrade -y -qq

# Install base dependencies
echo "[2/10] Installing base dependencies..."
apt-get install -y --no-install-recommends \
    curl wget git git-lfs jq ca-certificates gnupg sudo unzip \
    build-essential \
    python3 python3-pip python3-venv \
    netcat-openbsd dnsutils \
    tmux vim htop nvtop \
    linux-headers-$(uname -r)

# Install NVIDIA drivers + CUDA
echo "[3/10] Installing NVIDIA drivers and CUDA..."
if lspci | grep -i nvidia > /dev/null; then
    # Add NVIDIA package repositories
    distribution=$(. /etc/os-release;echo $ID$VERSION_ID | sed -e 's/\.//g')
    wget https://developer.download.nvidia.com/compute/cuda/repos/$distribution/x86_64/cuda-keyring_1.1-1_all.deb
    dpkg -i cuda-keyring_1.1-1_all.deb
    apt-get update -qq

    # Install CUDA toolkit and drivers
    apt-get install -y --no-install-recommends \
        cuda-toolkit-12-4 \
        nvidia-driver-550

    echo 'export PATH=/usr/local/cuda/bin:$PATH' >> /etc/profile.d/cuda.sh
    echo 'export LD_LIBRARY_PATH=/usr/local/cuda/lib64:$LD_LIBRARY_PATH' >> /etc/profile.d/cuda.sh

    echo "✓ NVIDIA drivers installed (reboot required for activation)"
else
    echo "⚠ No NVIDIA GPU detected, skipping driver installation"
fi

# Install Go 1.25.3
echo "[4/10] Installing Go 1.25.3..."
GO_VERSION=1.25.3
wget -q https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz -O /tmp/go.tar.gz
rm -rf /usr/local/go
tar -C /usr/local -xzf /tmp/go.tar.gz
rm /tmp/go.tar.gz
echo 'export PATH=/usr/local/go/bin:/root/go/bin:$PATH' >> /etc/profile.d/go.sh
echo 'export GOPATH=/root/go' >> /etc/profile.d/go.sh
export PATH=/usr/local/go/bin:$PATH
export GOPATH=/root/go

# Install Go development tools
go install golang.org/x/tools/gopls@latest
go install github.com/go-delve/delve/cmd/dlv@latest

# Install Ollama
echo "[5/10] Installing Ollama..."
curl -fsSL https://ollama.com/install.sh | sh
systemctl enable ollama
systemctl start ollama

# Wait for Ollama to start
sleep 5

# Pull models (this takes a while - 20-40GB per model)
echo "[6/10] Pulling LLM models (this will take 30-60 minutes)..."
ollama pull llama3.2:3b           # ~2GB  - fast, for testing
ollama pull qwen2.5:32b           # ~20GB - vulnerable per research paper
ollama pull deepseek-coder:6.7b   # ~4GB  - code generation
ollama pull llama3.1:8b           # ~5GB  - general purpose

echo "✓ Models pulled successfully"

# Python environment
echo "[7/10] Setting up Python environment..."
python3 -m venv /opt/venv
source /opt/venv/bin/activate
echo 'source /opt/venv/bin/activate' >> /root/.bashrc

pip install --no-cache-dir --upgrade pip setuptools wheel

# Install Python dependencies
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
echo "[8/10] Building Augustus..."
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
echo "[9/10] Creating research scripts..."
mkdir -p /workspace/results/{baseline,poetry}
mkdir -p /workspace/scripts

# Test providers script
cat > /workspace/scripts/test-providers.py << 'EOF'
#!/usr/bin/env python3
"""Test all configured LLM API providers and local Ollama."""
import os
import asyncio
from rich.console import Console
from rich.table import Table

console = Console()

async def test_provider(name, test_fn):
    try:
        result = await test_fn()
        return f"✅ {result}"
    except Exception as e:
        return f"❌ {str(e)[:40]}"

async def test_openai():
    if not os.environ.get("OPENAI_API_KEY"): return "⚪ No key"
    from openai import OpenAI
    client = OpenAI()
    r = client.chat.completions.create(model="gpt-4o-mini", messages=[{"role":"user","content":"Say OK"}], max_tokens=5)
    return r.choices[0].message.content

async def test_anthropic():
    if not os.environ.get("ANTHROPIC_API_KEY"): return "⚪ No key"
    import anthropic
    client = anthropic.Anthropic()
    r = client.messages.create(model="claude-3-haiku-20240307", max_tokens=5, messages=[{"role":"user","content":"Say OK"}])
    return r.content[0].text

async def test_google():
    if not os.environ.get("GOOGLE_API_KEY"): return "⚪ No key"
    import google.generativeai as genai
    genai.configure(api_key=os.environ["GOOGLE_API_KEY"])
    model = genai.GenerativeModel("gemini-1.5-flash")
    r = model.generate_content("Say OK")
    return r.text[:20]

async def test_ollama():
    import httpx
    async with httpx.AsyncClient() as client:
        r = await client.post("http://127.0.0.1:11434/api/generate",
            json={"model": "llama3.2:3b", "prompt": "Say OK", "stream": False},
            timeout=30.0)
        return r.json()["response"][:20]

async def main():
    console.print("\n[bold]LLM Provider Test[/bold]\n")
    table = Table()
    table.add_column("Provider", style="cyan")
    table.add_column("Status")

    for name, fn in [
        ("OpenAI", test_openai),
        ("Anthropic", test_anthropic),
        ("Google AI", test_google),
        ("Ollama (local)", test_ollama)
    ]:
        result = await test_provider(name, fn)
        table.add_row(name, result)

    console.print(table)

if __name__ == "__main__":
    asyncio.run(main())
EOF

# Baseline measurement script
cat > /workspace/scripts/run-baseline.sh << 'EOF'
#!/bin/bash
set -e
OUTPUT_DIR="${1:-/workspace/results/baseline}"
mkdir -p "$OUTPUT_DIR"
TS=$(date +%Y%m%d_%H%M%S)

echo "=== Phase B: Prose Baseline Measurement ==="
echo "Output: $OUTPUT_DIR"

PROBES="dan.*,encoding.*,smuggling.*,grandma.*,phrasing.*,poetry.*"
DET="mitigation.MitigationBypass"

run() {
    local GEN=$1 MODEL=$2 CONFIG=$3
    echo "Testing: $GEN / $MODEL"
    augustus scan -g "$GEN" -p "$PROBES" -d "$DET" -c "$CONFIG" \
        -o "$OUTPUT_DIR/${GEN}_${MODEL}_${TS}.jsonl" \
        --html "$OUTPUT_DIR/${GEN}_${MODEL}_${TS}.html" -v
}

# Local models (Ollama)
echo "=== Testing Local Models ==="
run "ollama.Ollama" "llama3.2" '{"model":"llama3.2:3b"}'
run "ollama.Ollama" "qwen2.5" '{"model":"qwen2.5:32b"}'
run "ollama.Ollama" "deepseek" '{"model":"deepseek-coder:6.7b"}'

# API providers
echo "=== Testing API Providers ==="
[ -n "$OPENAI_API_KEY" ] && run "openai.OpenAI" "gpt-4o" '{"model":"gpt-4o"}'
[ -n "$ANTHROPIC_API_KEY" ] && run "anthropic.Anthropic" "claude-3.5-sonnet" '{"model":"claude-3-5-sonnet-20241022"}'
[ -n "$GOOGLE_API_KEY" ] && run "google.GoogleAI" "gemini-1.5-pro" '{"model":"gemini-1.5-pro"}'

echo "✅ Baseline measurements complete! Results in $OUTPUT_DIR"
EOF

# ASR calculation script
cat > /workspace/scripts/calculate-asr.py << 'EOF'
#!/usr/bin/env python3
"""Calculate Attack Success Rate from Augustus results."""
import json
import sys
from pathlib import Path
import pandas as pd
from rich.console import Console
from rich.table import Table

console = Console()

def load_jsonl(f):
    return [json.loads(l) for l in open(f) if l.strip()]

def calc_asr(results):
    if not results: return {"total": 0, "bypassed": 0, "asr": 0.0}
    bypassed = sum(1 for r in results if r.get("score", 0) > 0.5)
    return {"total": len(results), "bypassed": bypassed, "asr": bypassed/len(results)*100}

def main():
    if len(sys.argv) < 2:
        console.print("[red]Usage:[/red] calculate-asr.py <baseline-dir>")
        sys.exit(1)

    base_dir = Path(sys.argv[1])

    console.print("\n[bold]Attack Success Rate Analysis[/bold]\n")

    table = Table()
    table.add_column("Model", style="cyan")
    table.add_column("Total", justify="right")
    table.add_column("Bypassed", justify="right")
    table.add_column("ASR", justify="right", style="bold")

    results = []
    for f in sorted(base_dir.glob("*.jsonl")):
        m = calc_asr(load_jsonl(f))
        m["model"] = f.stem
        results.append(m)
        table.add_row(
            m["model"][:40],
            str(m["total"]),
            str(m["bypassed"]),
            f"{m['asr']:.2f}%"
        )

    console.print(table)

    if results:
        avg_asr = sum(r["asr"] for r in results) / len(results)
        console.print(f"\n[bold]Average ASR:[/bold] {avg_asr:.2f}%\n")

if __name__ == "__main__":
    main()
EOF

chmod +x /workspace/scripts/*.sh /workspace/scripts/*.py

# Environment template
echo "[10/10] Creating environment template..."
cat > /workspace/.env.template << 'EOF'
# API Keys for LLM Providers
OPENAI_API_KEY=
ANTHROPIC_API_KEY=
GOOGLE_API_KEY=
TOGETHER_API_KEY=
GROQ_API_KEY=
EOF

# Setup info
cat > /workspace/README.txt << 'EOF'
Augustus Research Environment
=============================

## Setup
1. Copy API keys: cp .env.template .env && vim .env
2. Test providers: python3 scripts/test-providers.py
3. Run baseline: ./scripts/run-baseline.sh
4. Calculate ASR: python3 scripts/calculate-asr.py results/baseline

## Local Models (Ollama)
- llama3.2:3b      - Fast, testing
- qwen2.5:32b      - Vulnerable (per paper)
- deepseek-coder   - Code generation
- llama3.1:8b      - General purpose

## Commands
- augustus list               - List all capabilities
- augustus scan --help        - Show scan options
- ollama list                - List downloaded models
- nvidia-smi                 - Check GPU usage
- nvtop                      - GPU monitoring
EOF

# Cleanup
echo ""
echo "=========================================="
echo "Setup Complete!"
echo "=========================================="
echo ""
echo "Installed:"
echo "  ✓ Go $(go version | cut -d' ' -f3)"
echo "  ✓ Python $(python3 --version | cut -d' ' -f2)"
echo "  ✓ Augustus $(augustus --version 2>&1 || echo 'v0.1.0')"
echo "  ✓ Ollama $(ollama --version | head -1)"
echo "  ✓ NVIDIA drivers (reboot to activate)"
echo ""
echo "Models downloaded:"
ollama list
echo ""
echo "Next steps:"
echo "1. Reboot instance (for GPU drivers)"
echo "2. Create AMI from this instance:"
echo "   aws ec2 create-image --instance-id \$(ec2-metadata --instance-id | cut -d' ' -f2) \\"
echo "     --name augustus-research-$(date +%Y%m%d) \\"
echo "     --description 'Augustus LLM Research Environment'"
echo ""
