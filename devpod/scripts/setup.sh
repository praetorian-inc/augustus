#!/usr/bin/env bash
set -euo pipefail

###############################################################################
# Augustus Benchmark Setup
#
# Interactive script that walks users through configuring LLM providers
# for Augustus benchmarking. Writes configuration to ~/.augustus-benchmark.env
#
# Usage:
#   ./setup.sh          # Interactive provider selection
#   ./setup.sh --all    # Configure all providers non-interactively
#
# Idempotent: safe to re-run. Existing keys are preserved unless overwritten.
###############################################################################

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

readonly ENV_FILE="$HOME/.augustus-benchmark.env"
readonly SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"

# Colors
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly CYAN='\033[0;36m'
readonly BOLD='\033[1m'
readonly DIM='\033[2m'
readonly RESET='\033[0m'

# ---------------------------------------------------------------------------
# Provider registry
#
# Each provider is defined by a set of parallel arrays. This avoids
# duplicating selection/prompting/validation logic per provider (DRY).
# ---------------------------------------------------------------------------

# Display grouping
readonly -a PROVIDER_IDS=(
    ollama
    openai anthropic together groq mistral cohere fireworks deepinfra replicate
    azure bedrock vertex watsonx
    nvidia huggingface
)

readonly -a PROVIDER_NAMES=(
    "Ollama (DeepSeek, Qwen, Llama, Mistral, Phi, CodeLlama)"
    "OpenAI (GPT-4o, GPT-3.5, o1, o3)"
    "Anthropic (Claude 3/3.5/4)"
    "Together AI (DeepSeek, Qwen, Llama via cloud)"
    "Groq (fast inference - Llama, Mixtral)"
    "Mistral (Mistral API)"
    "Cohere (Command R)"
    "Fireworks (fast OSS model inference)"
    "DeepInfra (serverless GPU)"
    "Replicate (cloud-hosted models)"
    "Azure OpenAI (requires endpoint + deployment)"
    "AWS Bedrock (requires AWS credentials)"
    "Google Vertex AI (requires GCP project)"
    "IBM WatsonX (requires instance URL)"
    "NVIDIA NIM (requires API key)"
    "HuggingFace (Inference API + Endpoints)"
)

# Tier boundaries (indices into PROVIDER_IDS, 0-based)
readonly TIER_LOCAL_START=0  TIER_LOCAL_END=0
readonly TIER_CLOUD_START=1  TIER_CLOUD_END=9
readonly TIER_ENTERPRISE_START=10  TIER_ENTERPRISE_END=13
readonly TIER_SPECIALIZED_START=14  TIER_SPECIALIZED_END=15

# Provider -> primary env var (empty string means no single key)
declare -A PROVIDER_PRIMARY_KEY=(
    [ollama]=""
    [openai]="OPENAI_API_KEY"
    [anthropic]="ANTHROPIC_API_KEY"
    [together]="TOGETHER_API_KEY"
    [groq]="GROQ_API_KEY"
    [mistral]="MISTRAL_API_KEY"
    [cohere]="COHERE_API_KEY"
    [fireworks]="FIREWORKS_API_KEY"
    [deepinfra]="DEEPINFRA_API_KEY"
    [replicate]="REPLICATE_API_TOKEN"
    [azure]="AZURE_OPENAI_API_KEY"
    [bedrock]="AWS_ACCESS_KEY_ID"
    [vertex]="GOOGLE_APPLICATION_CREDENTIALS"
    [watsonx]="WATSONX_API_KEY"
    [nvidia]="NVIDIA_API_KEY"
    [huggingface]="HUGGINGFACE_API_KEY"
)

# Provider -> augustus generator name (for validation)
declare -A PROVIDER_GENERATOR=(
    [ollama]=""
    [openai]="openai.OpenAI"
    [anthropic]="anthropic.Anthropic"
    [together]="together.Together"
    [groq]="groq.Groq"
    [mistral]="mistral.Mistral"
    [cohere]="cohere.Cohere"
    [fireworks]="fireworks.Fireworks"
    [deepinfra]="deepinfra.DeepInfra"
    [replicate]="replicate.Replicate"
    [azure]=""
    [bedrock]=""
    [vertex]=""
    [watsonx]=""
    [nvidia]="nim.NIM"
    [huggingface]="huggingface.InferenceAPI"
)

# Provider -> default model (for validation)
declare -A PROVIDER_DEFAULT_MODEL=(
    [ollama]=""
    [openai]="gpt-4o"
    [anthropic]="claude-sonnet-4-20250514"
    [together]="meta-llama/Llama-3-70b-chat-hf"
    [groq]="llama-3.1-70b-versatile"
    [mistral]="mistral-large-latest"
    [cohere]="command-r-plus"
    [fireworks]="accounts/fireworks/models/llama-v3-70b-instruct"
    [deepinfra]="meta-llama/Llama-3-70b-instruct"
    [replicate]="meta/llama-2-70b-chat"
    [azure]=""
    [bedrock]=""
    [vertex]=""
    [watsonx]=""
    [nvidia]="meta/llama3-70b-instruct"
    [huggingface]="meta-llama/Llama-2-7b-chat-hf"
)

# ---------------------------------------------------------------------------
# Collected env vars (loaded from existing file or set during session)
# ---------------------------------------------------------------------------

declare -A ENV_VARS=()

# Track which providers were successfully configured this session
declare -a CONFIGURED_PROVIDERS=()
declare -a FAILED_PROVIDERS=()
declare -a SKIPPED_PROVIDERS=()

# ---------------------------------------------------------------------------
# Utility functions
# ---------------------------------------------------------------------------

print_header() {
    printf "\n${BOLD}${CYAN}=== %s ===${RESET}\n\n" "$1"
}

print_success() {
    printf "  ${GREEN}[OK]${RESET} %s\n" "$1"
}

print_fail() {
    printf "  ${RED}[FAIL]${RESET} %s\n" "$1"
}

print_warn() {
    printf "  ${YELLOW}[!]${RESET} %s\n" "$1"
}

print_info() {
    printf "  ${DIM}%s${RESET}\n" "$1"
}

# Read a value from the user, with optional default from existing env
# Usage: prompt_value "Prompt text" "ENV_VAR_NAME" [secret]
prompt_value() {
    local prompt_text="$1"
    local env_var_name="$2"
    local is_secret="${3:-}"

    local existing="${ENV_VARS[$env_var_name]:-}"
    local display_default=""

    if [[ -n "$existing" ]]; then
        if [[ "$is_secret" == "secret" ]]; then
            # Show only last 4 chars
            local len=${#existing}
            if (( len > 4 )); then
                display_default="****${existing: -4}"
            else
                display_default="****"
            fi
        else
            display_default="$existing"
        fi
    fi

    local full_prompt="    $prompt_text"
    if [[ -n "$display_default" ]]; then
        full_prompt+=" [${display_default}]"
    fi
    full_prompt+=": "

    local value
    if [[ "$is_secret" == "secret" ]]; then
        # Read without echo for secrets
        printf "%s" "$full_prompt"
        read -rs value
        printf "\n"
    else
        printf "%s" "$full_prompt"
        read -r value
    fi

    # Use existing value if user pressed enter
    if [[ -z "$value" && -n "$existing" ]]; then
        value="$existing"
    fi

    if [[ -z "$value" ]]; then
        return 1
    fi

    ENV_VARS[$env_var_name]="$value"
    return 0
}

# Set an env var directly
set_env_var() {
    ENV_VARS[$1]="$2"
}

# Check if augustus binary is available
has_augustus() {
    command -v augustus &>/dev/null
}

# Validate a provider by running a quick test scan
# Returns 0 on success, 1 on failure
validate_provider() {
    local generator="$1"
    local model="$2"

    if ! has_augustus; then
        print_warn "augustus binary not found -- skipping validation (keys saved)"
        return 0
    fi

    printf "    Validating..."

    # Export all current env vars for the subprocess
    for key in "${!ENV_VARS[@]}"; do
        export "$key"="${ENV_VARS[$key]}"
    done

    local output
    if output=$(augustus scan "$generator" --probe test.Blank --config "{\"model\":\"$model\"}" 2>&1); then
        printf "\r    ${GREEN}Validated successfully${RESET}              \n"
        return 0
    else
        printf "\r    ${RED}Validation failed${RESET}                     \n"
        print_info "Error: $output"
        return 1
    fi
}

# ---------------------------------------------------------------------------
# Load existing .env file
# ---------------------------------------------------------------------------

load_existing_env() {
    if [[ ! -f "$ENV_FILE" ]]; then
        return 0
    fi

    print_info "Loading existing configuration from $ENV_FILE"

    while IFS='=' read -r key value; do
        # Skip comments and empty lines
        [[ -z "$key" || "$key" =~ ^# ]] && continue
        # Remove surrounding quotes from value
        value="${value#\"}"
        value="${value%\"}"
        value="${value#\'}"
        value="${value%\'}"
        ENV_VARS[$key]="$value"
    done < "$ENV_FILE"
}

# Check which providers are already configured
show_existing_config() {
    local has_existing=false

    for id in "${PROVIDER_IDS[@]}"; do
        local primary_key="${PROVIDER_PRIMARY_KEY[$id]}"
        if [[ -n "$primary_key" && -n "${ENV_VARS[$primary_key]:-}" ]]; then
            if ! $has_existing; then
                printf "\n  ${GREEN}Already configured:${RESET}\n"
                has_existing=true
            fi
            local idx
            idx=$(provider_index "$id")
            printf "    ${GREEN}*${RESET} [%d] %s\n" "$((idx + 1))" "${PROVIDER_NAMES[$idx]}"
        fi
    done

    if $has_existing; then
        printf "\n"
    fi
}

# Get the index of a provider ID in PROVIDER_IDS
provider_index() {
    local target="$1"
    local i
    for i in "${!PROVIDER_IDS[@]}"; do
        if [[ "${PROVIDER_IDS[$i]}" == "$target" ]]; then
            printf "%d" "$i"
            return 0
        fi
    done
    return 1
}

# ---------------------------------------------------------------------------
# Provider configuration functions
# ---------------------------------------------------------------------------

# Configure a simple API key provider (most cloud providers)
configure_simple_provider() {
    local id="$1"
    local idx
    idx=$(provider_index "$id")
    local name="${PROVIDER_NAMES[$idx]}"
    local key_var="${PROVIDER_PRIMARY_KEY[$id]}"
    local generator="${PROVIDER_GENERATOR[$id]}"
    local model="${PROVIDER_DEFAULT_MODEL[$id]}"

    printf "\n  ${BOLD}Configuring %s${RESET}\n" "$name"

    if ! prompt_value "$key_var" "$key_var" "secret"; then
        print_warn "Skipped (no key provided)"
        SKIPPED_PROVIDERS+=("$id")
        return 0
    fi

    if [[ -n "$generator" && -n "$model" ]]; then
        if validate_provider "$generator" "$model"; then
            CONFIGURED_PROVIDERS+=("$id")
        else
            FAILED_PROVIDERS+=("$id")
            printf "    ${YELLOW}Key saved despite validation failure. You can fix and re-run.${RESET}\n"
        fi
    else
        CONFIGURED_PROVIDERS+=("$id")
    fi
}

# Configure Ollama (local models -- call pull-models.sh)
configure_ollama() {
    printf "\n  ${BOLD}Configuring Ollama (local models)${RESET}\n"

    # Check if Ollama is installed
    if ! command -v ollama &>/dev/null; then
        print_warn "Ollama is not installed."
        print_info "Install from: https://ollama.com/download"
        printf "    Continue anyway? (y/N): "
        local answer
        read -r answer
        if [[ ! "$answer" =~ ^[Yy] ]]; then
            SKIPPED_PROVIDERS+=("ollama")
            return 0
        fi
    else
        print_success "Ollama is installed"

        # Check if Ollama is running
        if ollama list &>/dev/null 2>&1; then
            print_success "Ollama service is running"
        else
            print_warn "Ollama service may not be running. Start with: ollama serve"
        fi
    fi

    # Call pull-models.sh if it exists
    local pull_script="$SCRIPT_DIR/pull-models.sh"
    if [[ -x "$pull_script" ]]; then
        printf "    Run model pull script? (Y/n): "
        local answer
        read -r answer
        if [[ ! "$answer" =~ ^[Nn] ]]; then
            "$pull_script"
        fi
    else
        print_info "No pull-models.sh found at $SCRIPT_DIR/pull-models.sh"
        print_info "You can pull models manually: ollama pull deepseek-r1"
    fi

    CONFIGURED_PROVIDERS+=("ollama")
}

# Configure Azure OpenAI (enterprise -- multiple fields)
configure_azure() {
    printf "\n  ${BOLD}Configuring Azure OpenAI${RESET}\n"
    print_info "Requires: API key, endpoint URL, and deployment name"

    if ! prompt_value "AZURE_OPENAI_API_KEY" "AZURE_OPENAI_API_KEY" "secret"; then
        print_warn "Skipped (no key provided)"
        SKIPPED_PROVIDERS+=("azure")
        return 0
    fi

    if ! prompt_value "AZURE_OPENAI_ENDPOINT (e.g. https://myresource.openai.azure.com)" "AZURE_OPENAI_ENDPOINT"; then
        print_warn "Skipped (no endpoint provided)"
        SKIPPED_PROVIDERS+=("azure")
        return 0
    fi

    if ! prompt_value "AZURE_OPENAI_DEPLOYMENT (e.g. gpt-4o-deployment)" "AZURE_OPENAI_DEPLOYMENT"; then
        print_warn "Skipped (no deployment name provided)"
        SKIPPED_PROVIDERS+=("azure")
        return 0
    fi

    print_success "Azure OpenAI configured"
    CONFIGURED_PROVIDERS+=("azure")
}

# Configure AWS Bedrock (enterprise -- AWS credentials)
configure_bedrock() {
    printf "\n  ${BOLD}Configuring AWS Bedrock${RESET}\n"
    print_info "Requires: AWS access key, secret key, and region"

    if ! prompt_value "AWS_ACCESS_KEY_ID" "AWS_ACCESS_KEY_ID" "secret"; then
        print_warn "Skipped (no access key provided)"
        SKIPPED_PROVIDERS+=("bedrock")
        return 0
    fi

    if ! prompt_value "AWS_SECRET_ACCESS_KEY" "AWS_SECRET_ACCESS_KEY" "secret"; then
        print_warn "Skipped (no secret key provided)"
        SKIPPED_PROVIDERS+=("bedrock")
        return 0
    fi

    if ! prompt_value "AWS_DEFAULT_REGION (e.g. us-east-1)" "AWS_DEFAULT_REGION"; then
        print_warn "Skipped (no region provided)"
        SKIPPED_PROVIDERS+=("bedrock")
        return 0
    fi

    print_success "AWS Bedrock configured"
    CONFIGURED_PROVIDERS+=("bedrock")
}

# Configure Google Vertex AI (enterprise -- GCP credentials)
configure_vertex() {
    printf "\n  ${BOLD}Configuring Google Vertex AI${RESET}\n"
    print_info "Requires: path to service account JSON and GCP project ID"

    if ! prompt_value "GOOGLE_APPLICATION_CREDENTIALS (path to service account JSON)" "GOOGLE_APPLICATION_CREDENTIALS"; then
        print_warn "Skipped (no credentials path provided)"
        SKIPPED_PROVIDERS+=("vertex")
        return 0
    fi

    local cred_path="${ENV_VARS[GOOGLE_APPLICATION_CREDENTIALS]}"
    if [[ ! -f "$cred_path" ]]; then
        print_warn "Credentials file not found: $cred_path"
        print_info "Saving path anyway -- ensure the file exists before running benchmarks"
    fi

    if ! prompt_value "GCP_PROJECT_ID" "GCP_PROJECT_ID"; then
        print_warn "Skipped (no project ID provided)"
        SKIPPED_PROVIDERS+=("vertex")
        return 0
    fi

    print_success "Google Vertex AI configured"
    CONFIGURED_PROVIDERS+=("vertex")
}

# Configure IBM WatsonX (enterprise -- instance URL + project)
configure_watsonx() {
    printf "\n  ${BOLD}Configuring IBM WatsonX${RESET}\n"
    print_info "Requires: API key, instance URL, and project ID"

    if ! prompt_value "WATSONX_API_KEY" "WATSONX_API_KEY" "secret"; then
        print_warn "Skipped (no key provided)"
        SKIPPED_PROVIDERS+=("watsonx")
        return 0
    fi

    if ! prompt_value "WATSONX_URL (e.g. https://us-south.ml.cloud.ibm.com)" "WATSONX_URL"; then
        print_warn "Skipped (no URL provided)"
        SKIPPED_PROVIDERS+=("watsonx")
        return 0
    fi

    if ! prompt_value "WATSONX_PROJECT_ID" "WATSONX_PROJECT_ID"; then
        print_warn "Skipped (no project ID provided)"
        SKIPPED_PROVIDERS+=("watsonx")
        return 0
    fi

    print_success "IBM WatsonX configured"
    CONFIGURED_PROVIDERS+=("watsonx")
}

# ---------------------------------------------------------------------------
# Dispatch: route provider ID to configuration function
# ---------------------------------------------------------------------------

configure_provider() {
    local id="$1"

    case "$id" in
        ollama)     configure_ollama ;;
        azure)      configure_azure ;;
        bedrock)    configure_bedrock ;;
        vertex)     configure_vertex ;;
        watsonx)    configure_watsonx ;;
        # All simple API key providers use the generic function
        openai|anthropic|together|groq|mistral|cohere|fireworks|deepinfra|replicate|nvidia|huggingface)
            configure_simple_provider "$id"
            ;;
        *)
            print_fail "Unknown provider: $id"
            return 1
            ;;
    esac
}

# ---------------------------------------------------------------------------
# Write .env file
# ---------------------------------------------------------------------------

write_env_file() {
    local tmp_file
    tmp_file=$(mktemp) || { print_fail "Failed to create temp file"; return 1; }

    {
        printf "# Augustus Benchmark Environment Configuration\n"
        printf "# Generated by setup.sh on %s\n" "$(date -u +"%Y-%m-%dT%H:%M:%SZ")"
        printf "# Re-run setup.sh to add or update providers.\n"
        printf "#\n"
        printf "# Source this file before running benchmarks:\n"
        printf "#   source %s\n" "$ENV_FILE"
        printf "\n"

        # Sort keys for deterministic output
        local sorted_keys
        sorted_keys=$(printf '%s\n' "${!ENV_VARS[@]}" | sort)

        local prev_prefix=""
        while IFS= read -r key; do
            [[ -z "$key" ]] && continue
            local value="${ENV_VARS[$key]}"

            # Group by prefix (OPENAI_, ANTHROPIC_, etc.) with blank lines
            local prefix="${key%%_*}"
            if [[ "$prefix" != "$prev_prefix" && -n "$prev_prefix" ]]; then
                printf "\n"
            fi
            prev_prefix="$prefix"

            # Quote value if it contains special characters
            if [[ "$value" =~ [[:space:]\#\$\`\\] ]]; then
                printf '%s="%s"\n' "$key" "$value"
            else
                printf '%s=%s\n' "$key" "$value"
            fi
        done <<< "$sorted_keys"
    } > "$tmp_file"

    # Atomic write
    mv "$tmp_file" "$ENV_FILE"
    chmod 600 "$ENV_FILE"

    print_success "Configuration written to $ENV_FILE"
}

# ---------------------------------------------------------------------------
# Display provider selection menu
# ---------------------------------------------------------------------------

show_menu() {
    print_header "Augustus Benchmark Setup"

    printf "  Select providers to configure:\n"

    # Helper to print a tier section
    print_tier() {
        local tier_label="$1"
        local start="$2"
        local end="$3"

        printf "\n  ${BOLD}%s:${RESET}\n" "$tier_label"
        local i
        for (( i = start; i <= end; i++ )); do
            local marker=""
            local key="${PROVIDER_PRIMARY_KEY[${PROVIDER_IDS[$i]}]}"
            if [[ -n "$key" && -n "${ENV_VARS[$key]:-}" ]]; then
                marker=" ${GREEN}*${RESET}"
            fi
            printf "    ${BOLD}[%2d]${RESET} %s%b\n" "$((i + 1))" "${PROVIDER_NAMES[$i]}" "$marker"
        done
    }

    print_tier "LOCAL MODELS (requires GPU instance)" $TIER_LOCAL_START $TIER_LOCAL_END
    print_tier "CLOUD APIs" $TIER_CLOUD_START $TIER_CLOUD_END
    print_tier "ENTERPRISE" $TIER_ENTERPRISE_START $TIER_ENTERPRISE_END
    print_tier "SPECIALIZED" $TIER_SPECIALIZED_START $TIER_SPECIALIZED_END

    printf "\n  ${DIM}UTILITY (no setup needed):${RESET}\n"
    printf "    ${DIM}REST, Function, Test generators - always available${RESET}\n"

    printf "\n  ${GREEN}*${RESET} = already configured\n"
}

# ---------------------------------------------------------------------------
# Parse user selection
# ---------------------------------------------------------------------------

parse_selection() {
    local input="$1"
    local -a selected=()

    # Trim whitespace
    input="${input// /}"

    if [[ "$input" == "all" || "$input" == "ALL" ]]; then
        selected=("${PROVIDER_IDS[@]}")
    else
        # Split on commas
        IFS=',' read -ra tokens <<< "$input"
        for token in "${tokens[@]}"; do
            # Handle ranges like "2-5"
            if [[ "$token" =~ ^([0-9]+)-([0-9]+)$ ]]; then
                local range_start="${BASH_REMATCH[1]}"
                local range_end="${BASH_REMATCH[2]}"
                for (( n = range_start; n <= range_end; n++ )); do
                    local idx=$((n - 1))
                    if (( idx >= 0 && idx < ${#PROVIDER_IDS[@]} )); then
                        selected+=("${PROVIDER_IDS[$idx]}")
                    else
                        print_warn "Invalid number: $n (valid: 1-${#PROVIDER_IDS[@]})"
                    fi
                done
            elif [[ "$token" =~ ^[0-9]+$ ]]; then
                local idx=$((token - 1))
                if (( idx >= 0 && idx < ${#PROVIDER_IDS[@]} )); then
                    selected+=("${PROVIDER_IDS[$idx]}")
                else
                    print_warn "Invalid number: $token (valid: 1-${#PROVIDER_IDS[@]})"
                fi
            elif [[ -n "$token" ]]; then
                print_warn "Invalid input: $token"
            fi
        done
    fi

    # Deduplicate while preserving order
    local -A seen=()
    local -a unique=()
    for id in "${selected[@]}"; do
        if [[ -z "${seen[$id]:-}" ]]; then
            seen[$id]=1
            unique+=("$id")
        fi
    done

    printf '%s\n' "${unique[@]}"
}

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

show_summary() {
    print_header "Setup Summary"

    if [[ ${#CONFIGURED_PROVIDERS[@]} -gt 0 ]]; then
        printf "  ${GREEN}Configured and ready:${RESET}\n"
        for id in "${CONFIGURED_PROVIDERS[@]}"; do
            local idx
            idx=$(provider_index "$id")
            printf "    ${GREEN}[OK]${RESET} %s\n" "${PROVIDER_NAMES[$idx]}"
        done
    fi

    if [[ ${#FAILED_PROVIDERS[@]} -gt 0 ]]; then
        printf "\n  ${RED}Configured but validation failed:${RESET}\n"
        for id in "${FAILED_PROVIDERS[@]}"; do
            local idx
            idx=$(provider_index "$id")
            printf "    ${RED}[!!]${RESET} %s\n" "${PROVIDER_NAMES[$idx]}"
        done
    fi

    if [[ ${#SKIPPED_PROVIDERS[@]} -gt 0 ]]; then
        printf "\n  ${YELLOW}Skipped:${RESET}\n"
        for id in "${SKIPPED_PROVIDERS[@]}"; do
            local idx
            idx=$(provider_index "$id")
            printf "    ${DIM}[ ]${RESET}  %s\n" "${PROVIDER_NAMES[$idx]}"
        done
    fi

    # Show providers that were configured before this session
    local -a previously_configured=()
    for id in "${PROVIDER_IDS[@]}"; do
        local key="${PROVIDER_PRIMARY_KEY[$id]}"
        if [[ -z "$key" && "$id" != "ollama" ]]; then
            continue
        fi

        # Skip if handled in this session
        local dominated=false
        for cid in "${CONFIGURED_PROVIDERS[@]}" "${FAILED_PROVIDERS[@]}" "${SKIPPED_PROVIDERS[@]}"; do
            if [[ "$cid" == "$id" ]]; then
                dominated=true
                break
            fi
        done
        if $dominated; then
            continue
        fi

        if [[ -n "$key" && -n "${ENV_VARS[$key]:-}" ]]; then
            previously_configured+=("$id")
        fi
    done

    if [[ ${#previously_configured[@]} -gt 0 ]]; then
        printf "\n  ${CYAN}Previously configured (unchanged):${RESET}\n"
        for id in "${previously_configured[@]}"; do
            local idx
            idx=$(provider_index "$id")
            printf "    ${CYAN}[-]${RESET}  %s\n" "${PROVIDER_NAMES[$idx]}"
        done
    fi

    printf "\n  ${DIM}Always available: REST, Function, Test generators${RESET}\n"

    printf "\n  Configuration file: ${BOLD}%s${RESET}\n" "$ENV_FILE"
    printf "  To use: ${CYAN}source %s${RESET}\n\n" "$ENV_FILE"
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

main() {
    # Load existing configuration
    load_existing_env

    # Handle --all flag
    if [[ "${1:-}" == "--all" ]]; then
        print_header "Augustus Benchmark Setup (all providers)"
        show_existing_config
        for id in "${PROVIDER_IDS[@]}"; do
            configure_provider "$id"
        done
        write_env_file
        show_summary
        return 0
    fi

    # Interactive mode
    show_menu
    show_existing_config

    printf "  Enter numbers (comma-separated, ranges like 2-5, or 'all'): "
    local selection
    read -r selection

    if [[ -z "$selection" ]]; then
        printf "\n  No providers selected. Exiting.\n\n"
        return 0
    fi

    # Parse selection into provider IDs
    local -a selected_ids
    mapfile -t selected_ids < <(parse_selection "$selection")

    if [[ ${#selected_ids[@]} -eq 0 ]]; then
        printf "\n  No valid providers selected. Exiting.\n\n"
        return 0
    fi

    printf "\n  Configuring %d provider(s)...\n" "${#selected_ids[@]}"

    for id in "${selected_ids[@]}"; do
        configure_provider "$id"
    done

    # Write .env file if any env vars were set
    if [[ ${#ENV_VARS[@]} -gt 0 ]]; then
        printf "\n"
        write_env_file
    fi

    show_summary
}

main "$@"
