#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# Ollama Model Pull Script for Augustus Benchmark DevPod
#
# Helps users pull local LLM models via Ollama, grouped by VRAM requirements.
# Detects available GPU VRAM and recommends appropriate model tiers.
# =============================================================================

# ---------------------------------------------------------------------------
# Colors
# ---------------------------------------------------------------------------
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
DIM='\033[2m'
NC='\033[0m' # No Color

# ---------------------------------------------------------------------------
# Logging helpers
# ---------------------------------------------------------------------------
info()  { printf "${GREEN}[INFO]${NC}  %s\n" "$*"; }
warn()  { printf "${YELLOW}[WARN]${NC}  %s\n" "$*" >&2; }
error() { printf "${RED}[ERROR]${NC} %s\n" "$*" >&2; }

# ---------------------------------------------------------------------------
# Model registry
#
# Format: TAG|DESCRIPTION|ESTIMATED_SIZE|TIER
# ---------------------------------------------------------------------------
declare -a MODEL_REGISTRY=(
    # Tier 1 - Lightweight (<=8GB VRAM)
    "llama3.2:3b|Meta Llama 3.2 3B (fast, minimal)|~2.0 GB|1"
    "llama3.2:1b|Meta Llama 3.2 1B (ultrafast)|~1.3 GB|1"
    "phi3:medium|Microsoft Phi-3 (3.8B, efficient)|~2.3 GB|1"
    "mistral:7b|Mistral 7B (balanced)|~4.1 GB|1"
    "qwen2.5:7b|Qwen 2.5 7B (general purpose)|~4.7 GB|1"
    # Tier 2 - Standard (<=16GB VRAM)
    "llama3.1:8b|Meta Llama 3.1 8B|~4.7 GB|2"
    "deepseek-r1:8b|DeepSeek R1 8B (reasoning)|~4.9 GB|2"
    "deepseek-r1:14b|DeepSeek R1 14B (reasoning)|~9.0 GB|2"
    "qwen2.5:14b|Qwen 2.5 14B (general purpose)|~9.0 GB|2"
    "codellama:13b|Code Llama 13B (code specialist)|~7.4 GB|2"
    # Tier 3 - Pro (<=24GB VRAM)
    "qwen2.5:32b|Qwen 2.5 32B|~20 GB|3"
    "deepseek-r1:32b|DeepSeek R1 32B (reasoning)|~20 GB|3"
    "llama3.1:70b-q4|Llama 3.1 70B (4-bit quantized, tight fit)|~22 GB|3"
)

# ---------------------------------------------------------------------------
# GPU / VRAM detection
# ---------------------------------------------------------------------------
detect_vram() {
    local vram_mb=0
    local gpu_name="(not detected)"

    if command -v nvidia-smi &>/dev/null; then
        # Try to get total memory in MiB from nvidia-smi
        vram_mb=$(nvidia-smi --query-gpu=memory.total --format=csv,noheader,nounits 2>/dev/null | head -n1 | tr -d '[:space:]') || true
        gpu_name=$(nvidia-smi --query-gpu=name --format=csv,noheader 2>/dev/null | head -n1 | xargs) || true

        if [[ -z "$vram_mb" || "$vram_mb" == "0" ]]; then
            vram_mb=0
            gpu_name="(not detected)"
        fi
    fi

    echo "${vram_mb}|${gpu_name}"
}

recommend_tier() {
    local vram_mb="$1"
    if [[ "$vram_mb" -eq 0 ]]; then
        echo "unknown"
    elif [[ "$vram_mb" -le 8192 ]]; then
        echo "1"
    elif [[ "$vram_mb" -le 16384 ]]; then
        echo "2"
    else
        echo "3"
    fi
}

tier_label() {
    case "$1" in
        1) echo "Lightweight (<=8GB)" ;;
        2) echo "Standard (<=16GB)" ;;
        3) echo "Pro (<=24GB)" ;;
        *) echo "Unknown" ;;
    esac
}

vram_threshold_mb() {
    case "$1" in
        1) echo 8192 ;;
        2) echo 16384 ;;
        3) echo 24576 ;;
        *) echo 0 ;;
    esac
}

# ---------------------------------------------------------------------------
# Ensure Ollama is running
# ---------------------------------------------------------------------------
ensure_ollama() {
    if ! command -v ollama &>/dev/null; then
        error "Ollama is not installed. Install it from https://ollama.com"
        exit 1
    fi

    # Check if ollama is already serving
    if ! ollama list &>/dev/null 2>&1; then
        info "Ollama does not appear to be running. Starting ollama serve..."
        ollama serve &>/dev/null &
        local ollama_pid=$!
        # Give it a moment to start
        local retries=0
        while ! ollama list &>/dev/null 2>&1; do
            sleep 1
            retries=$((retries + 1))
            if [[ $retries -ge 10 ]]; then
                error "Failed to start ollama serve after 10 seconds."
                error "Try running 'ollama serve' manually in another terminal."
                exit 1
            fi
        done
        info "Ollama is now running (PID: ${ollama_pid})."
    else
        info "Ollama is already running."
    fi
}

# ---------------------------------------------------------------------------
# Display model menu
# ---------------------------------------------------------------------------
display_menu() {
    local vram_mb="$1"
    local gpu_name="$2"
    local recommended_tier="$3"

    printf "\n${BOLD}=== Ollama Model Manager ===${NC}\n\n"

    if [[ "$vram_mb" -gt 0 ]]; then
        local vram_gb
        vram_gb=$(awk "BEGIN {printf \"%.0f\", ${vram_mb}/1024}")
        printf "Detected GPU: ${CYAN}%s (%sGB VRAM)${NC}\n" "$gpu_name" "$vram_gb"
        printf "Recommended tier: ${GREEN}%s${NC}\n" "$(tier_label "$recommended_tier")"
    else
        printf "Detected GPU: ${DIM}None detected (CPU-only mode)${NC}\n"
        printf "Recommended tier: ${GREEN}Lightweight (<=8GB) for CPU${NC}\n"
    fi

    local idx=0
    local current_tier=""

    for entry in "${MODEL_REGISTRY[@]}"; do
        idx=$((idx + 1))
        local tier="${entry##*|}"
        local tag="${entry%%|*}"
        local rest="${entry#*|}"
        local desc="${rest%%|*}"
        rest="${rest#*|}"
        local size="${rest%%|*}"

        # Print tier header when tier changes
        if [[ "$tier" != "$current_tier" ]]; then
            case "$tier" in
                1) printf "\n${BOLD}${BLUE}LIGHTWEIGHT (<=8GB VRAM):${NC}\n" ;;
                2) printf "\n${BOLD}${BLUE}STANDARD (<=16GB VRAM - g4dn.xlarge T4):${NC}\n" ;;
                3) printf "\n${BOLD}${BLUE}PRO (<=24GB VRAM - g6.xlarge L4):${NC}\n" ;;
            esac
            current_tier="$tier"
        fi

        printf "  ${BOLD}[%2d]${NC} %-22s - %s ${DIM}(%s)${NC}\n" "$idx" "$tag" "$desc" "$size"
    done

    printf "\n"
}

# ---------------------------------------------------------------------------
# Parse selection into list of indices (1-based)
# ---------------------------------------------------------------------------
parse_selection() {
    local input="$1"
    local total="$2"
    local -a indices=()

    # Trim whitespace
    input=$(echo "$input" | xargs)

    # Handle tier shortcuts
    case "$input" in
        tier1)
            for i in $(seq 1 "$total"); do
                local entry="${MODEL_REGISTRY[$((i - 1))]}"
                local tier="${entry##*|}"
                [[ "$tier" == "1" ]] && indices+=("$i")
            done
            ;;
        tier2)
            for i in $(seq 1 "$total"); do
                local entry="${MODEL_REGISTRY[$((i - 1))]}"
                local tier="${entry##*|}"
                [[ "$tier" == "2" ]] && indices+=("$i")
            done
            ;;
        tier3)
            for i in $(seq 1 "$total"); do
                local entry="${MODEL_REGISTRY[$((i - 1))]}"
                local tier="${entry##*|}"
                [[ "$tier" == "3" ]] && indices+=("$i")
            done
            ;;
        all)
            for i in $(seq 1 "$total"); do
                indices+=("$i")
            done
            ;;
        *)
            # Comma-separated numbers
            IFS=',' read -ra parts <<< "$input"
            for part in "${parts[@]}"; do
                local num
                num=$(echo "$part" | tr -d '[:space:]')
                if [[ "$num" =~ ^[0-9]+$ ]] && [[ "$num" -ge 1 ]] && [[ "$num" -le "$total" ]]; then
                    indices+=("$num")
                else
                    warn "Ignoring invalid selection: '$num' (must be 1-${total})"
                fi
            done
            ;;
    esac

    echo "${indices[*]}"
}

# ---------------------------------------------------------------------------
# Pull selected models
# ---------------------------------------------------------------------------
pull_models() {
    local -a indices=("$@")
    local total=${#indices[@]}
    local count=0
    local vram_mb="${DETECTED_VRAM_MB:-0}"

    for idx in "${indices[@]}"; do
        count=$((count + 1))
        local entry="${MODEL_REGISTRY[$((idx - 1))]}"
        local tag="${entry%%|*}"
        local rest="${entry#*|}"
        local desc="${rest%%|*}"
        rest="${rest#*|}"
        local size="${rest%%|*}"
        local tier="${entry##*|}"

        printf "\n${BOLD}[%d/%d]${NC} Pulling ${CYAN}%s${NC} - %s ${DIM}(%s)${NC}\n" \
            "$count" "$total" "$tag" "$desc" "$size"

        # Warn if model tier exceeds detected VRAM
        if [[ "$vram_mb" -gt 0 ]]; then
            local tier_threshold
            tier_threshold=$(vram_threshold_mb "$tier")
            if [[ "$vram_mb" -lt "$tier_threshold" ]]; then
                warn "This model (tier ${tier}) may exceed your detected VRAM (${vram_mb}MB)."
                warn "It may run slowly or fail to load on GPU. CPU fallback will be used."
            fi
        fi

        printf "${DIM}─────────────────────────────────────────${NC}\n"

        if ! ollama pull "$tag"; then
            error "Failed to pull ${tag}. Continuing with remaining models..."
        else
            info "Successfully pulled ${tag}."
        fi
    done
}

# ---------------------------------------------------------------------------
# Show pulled models and disk usage
# ---------------------------------------------------------------------------
show_summary() {
    printf "\n${BOLD}=== Pulled Models ===${NC}\n\n"
    ollama list 2>/dev/null || warn "Could not list models."
    printf "\n"

    # Show disk usage of ollama models directory if it exists
    local ollama_dir=""
    if [[ -d "$HOME/.ollama/models" ]]; then
        ollama_dir="$HOME/.ollama/models"
    elif [[ -d "/usr/share/ollama/.ollama/models" ]]; then
        ollama_dir="/usr/share/ollama/.ollama/models"
    fi

    if [[ -n "$ollama_dir" ]]; then
        local disk_usage
        disk_usage=$(du -sh "$ollama_dir" 2>/dev/null | cut -f1) || disk_usage="unknown"
        printf "${BOLD}Total model disk usage:${NC} %s (%s)\n\n" "$disk_usage" "$ollama_dir"
    fi
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
main() {
    ensure_ollama

    # Detect VRAM
    local vram_info
    vram_info=$(detect_vram)
    local vram_mb="${vram_info%%|*}"
    local gpu_name="${vram_info#*|}"
    export DETECTED_VRAM_MB="$vram_mb"

    local recommended_tier
    recommended_tier=$(recommend_tier "$vram_mb")

    # Warn if no GPU detected - Ollama will use CPU (very slow for large models)
    if [[ "$vram_mb" -eq 0 ]]; then
        printf "\n${YELLOW}${BOLD}WARNING: No GPU detected.${NC}\n"
        printf "${YELLOW}Local models will run on CPU, which is significantly slower.${NC}\n"
        printf "${YELLOW}For best results, use a GPU instance (make devpod-up-gpu) or cloud APIs.${NC}\n"
        printf "${YELLOW}Lightweight models (Tier 1) are recommended for CPU-only instances.${NC}\n\n"
        printf "Continue anyway? [y/N]: "
        read -r confirm
        if [[ "${confirm,,}" != "y" ]]; then
            info "Exiting. Use cloud APIs via setup.sh for CPU-only instances."
            exit 0
        fi
    fi

    local total_models=${#MODEL_REGISTRY[@]}

    display_menu "$vram_mb" "$gpu_name" "$recommended_tier"

    printf "Enter numbers (comma-separated), '${BOLD}tier1${NC}', '${BOLD}tier2${NC}', '${BOLD}tier3${NC}', or '${BOLD}all${NC}': "
    read -r selection

    if [[ -z "$selection" ]]; then
        info "No selection made. Exiting."
        exit 0
    fi

    local indices_str
    indices_str=$(parse_selection "$selection" "$total_models")

    if [[ -z "$indices_str" ]]; then
        warn "No valid models selected. Exiting."
        exit 0
    fi

    # Convert string back to array
    read -ra selected_indices <<< "$indices_str"

    local selected_count=${#selected_indices[@]}
    printf "\n${BOLD}Pulling %d model(s)...${NC}\n" "$selected_count"

    pull_models "${selected_indices[@]}"

    show_summary

    info "Model pull complete."
}

main "$@"
