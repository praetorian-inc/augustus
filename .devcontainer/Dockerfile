FROM mcr.microsoft.com/devcontainers/base:noble

# Alleviate bad proxies
RUN touch /etc/apt/apt.conf.d/99fixbadproxy && \
    echo "Acquire::http::Pipeline-Depth 0;" >> /etc/apt/apt.conf.d/99fixbadproxy && \
    echo "Acquire::http::No-Cache true;" >> /etc/apt/apt.conf.d/99fixbadproxy && \
    echo "Acquire::BrokenProxy true;" >> /etc/apt/apt.conf.d/99fixbadproxy

# Install Node.js 22+
RUN curl -fsSL https://deb.nodesource.com/setup_22.x | bash -

# Install system packages
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y \
        nodejs \
        git \
        curl \
        jq \
        gh \
        python3 \
        python3-pip \
        python3-venv \
        openjdk-21-jre-headless \
        zstd \
    && apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Install Go 1.25.3
ARG GO_VERSION=1.25.3
RUN curl -fsSL https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz -o /tmp/go.tar.gz && \
    rm -rf /usr/local/go && \
    tar -C /usr/local -xzf /tmp/go.tar.gz && \
    rm /tmp/go.tar.gz
ENV PATH="/usr/local/go/bin:/home/vscode/go/bin:${PATH}"
ENV GOPATH="/home/vscode/go"

# Install Go tools
RUN GOPATH=/tmp/gotools go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest && \
    mkdir -p /home/vscode/go/bin && \
    cp /tmp/gotools/bin/* /home/vscode/go/bin/ && \
    chown -R vscode:vscode /home/vscode/go 2>/dev/null || true && \
    rm -rf /tmp/gotools

# Install Ollama (local model runner)
RUN curl -fsSL https://ollama.com/install.sh | sh

# Install npm packages globally
RUN npm install -g \
    @anthropic-ai/claude-code \
    typescript

# Install Python packages (LiteLLM for unified API proxy)
RUN pip3 install --break-system-packages litellm

# Setup directories with proper ownership
RUN mkdir -p /home/vscode/workspace /home/vscode/.ollama /home/vscode/go && \
    chown -R vscode:vscode /home/vscode

USER vscode
WORKDIR /home/vscode

# Configure npm for user-local installs
RUN mkdir -p /home/vscode/.npm-global && \
    npm config set prefix '/home/vscode/.npm-global'

ENV PATH="/home/vscode/.npm-global/bin:$PATH"
ENV OLLAMA_HOST="http://0.0.0.0:11434"
