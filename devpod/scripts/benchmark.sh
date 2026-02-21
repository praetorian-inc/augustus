#!/usr/bin/env bash
set -euo pipefail

###############################################################################
# benchmark.sh - Augustus LLM Benchmark Runner
#
# Runs Augustus red-teaming scans against multiple LLM providers and produces
# comparison reports. Uses YAML config files for scan settings.
#
# Modes:
#   A) Basic (default) - Run scans, save per-provider JSONL + HTML
#   B) Compare (--compare) - Basic + comparison matrix (MD + CSV)
#   C) Full (--full) - Compare + timing, cost estimates, executive summary
#
# Usage:
#   benchmark.sh --providers "ollama:deepseek-r1:14b,openai:gpt-4o" --probes "dan.*"
#   benchmark.sh --providers "ollama:model,openai:gpt-4o" --probes "dan.*" --compare
#   benchmark.sh --providers "ollama:model,openai:gpt-4o" --probes "dan.*" --full
#   benchmark.sh --providers "ollama:model" --all --dry-run
#   benchmark.sh --providers "openai:gpt-4o" --probes "dan.*" --config-file my-config.yaml
#
###############################################################################

# -- Colors ------------------------------------------------------------------

readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly CYAN='\033[0;36m'
readonly BOLD='\033[1m'
readonly NC='\033[0m' # No Color

# -- Logging -----------------------------------------------------------------

log_info()  { printf "${GREEN}[INFO]${NC}  %s\n" "$*" >&2; }
log_warn()  { printf "${YELLOW}[WARN]${NC}  %s\n" "$*" >&2; }
log_error() { printf "${RED}[ERROR]${NC} %s\n" "$*" >&2; }
log_step()  { printf "${CYAN}[STEP]${NC}  %s\n" "$*" >&2; }
log_bold()  { printf "${BOLD}%s${NC}\n" "$*" >&2; }

# -- Script directory detection -----------------------------------------------

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
SCRIPT_NAME="$(basename -- "${BASH_SOURCE[0]}")"

# Resolve WORKSPACE_DIR: the devpod/ directory containing configs/ and scripts/
# Scripts live in devpod/scripts/, so go up one level to devpod/
WORKSPACE_DIR="$(cd "${SCRIPT_DIR}/.." && pwd -P)"

# -- Defaults -----------------------------------------------------------------

PROVIDERS=""
PROBES=""
BUFFS=""
ALL_PROBES=false
MODE="basic"        # basic | compare | full
DRY_RUN=false
ENV_FILE="${HOME}/.augustus-benchmark.env"
CONFIG_FILE="${WORKSPACE_DIR}/configs/base.yaml"

# -- Provider alias map -------------------------------------------------------
# Maps short aliases to full Augustus generator class names.
# These MUST match the registered names in Augustus (see internal/generators/).

resolve_generator() {
    local alias="$1"
    case "$alias" in
        ollama)             echo "ollama.OllamaChat" ;;
        openai)             echo "openai.OpenAI" ;;
        anthropic)          echo "anthropic.Anthropic" ;;
        huggingface|hf)     echo "huggingface.InferenceAPI" ;;
        cohere)             echo "cohere.Cohere" ;;
        replicate)          echo "replicate.Replicate" ;;
        vertex|google|gemini) echo "vertex.Vertex" ;;
        mistral)            echo "mistral.Mistral" ;;
        together)           echo "together.Together" ;;
        groq)               echo "groq.Groq" ;;
        fireworks)          echo "fireworks.Fireworks" ;;
        deepinfra)          echo "deepinfra.DeepInfra" ;;
        azure)              echo "azure.AzureOpenAI" ;;
        bedrock)            echo "bedrock.Bedrock" ;;
        nim)                echo "nim.NIM" ;;
        watsonx)            echo "watsonx.WatsonX" ;;
        litellm)            echo "litellm.LiteLLM" ;;
        rest)               echo "rest.Rest" ;;
        *)                  echo "$alias" ;;  # Pass through if already fully qualified
    esac
}

# -- Cost lookup table (USD per 1M input tokens) -----------------------------

get_cost_per_million() {
    local model="$1"
    case "$model" in
        gpt-4o)                 echo "2.50" ;;
        gpt-4o-mini)            echo "0.15" ;;
        gpt-4-turbo*)           echo "10.00" ;;
        gpt-4)                  echo "30.00" ;;
        gpt-3.5-turbo*)         echo "0.50" ;;
        claude-3-5-sonnet*|claude-3.5-sonnet*|claude-sonnet*) echo "3.00" ;;
        claude-3-opus*|claude-opus*) echo "15.00" ;;
        claude-3-haiku*|claude-haiku*) echo "0.25" ;;
        gemini-1.5-pro*)        echo "1.25" ;;
        gemini-1.5-flash*)      echo "0.075" ;;
        mistral-large*)         echo "2.00" ;;
        mistral-small*)         echo "0.20" ;;
        command-r-plus*)        echo "2.50" ;;
        command-r*)             echo "0.15" ;;
        *)                      echo "" ;;  # Unknown - no cost estimate
    esac
}

# -- Usage --------------------------------------------------------------------

usage() {
    cat <<EOF
${BOLD}Augustus Benchmark Runner${NC}

Run Augustus red-teaming scans against multiple LLM providers and produce
comparison reports.

${BOLD}USAGE${NC}
    $SCRIPT_NAME [OPTIONS]

${BOLD}OPTIONS${NC}
    --providers LIST    Comma-separated provider:model pairs (required)
                        Short aliases: ollama, openai, anthropic, vertex,
                        huggingface, cohere, replicate, mistral, together,
                        groq, fireworks, deepinfra, azure, bedrock, nim,
                        watsonx, litellm, rest
                        Example: "ollama:deepseek-r1:14b,openai:gpt-4o"

    --probes PATTERN    Probe glob pattern(s), comma-separated
                        Example: "dan.*,encoding.*"

    --buffs PATTERN     Buff glob pattern(s), comma-separated
                        Example: "poetry.MetaPrompt,conlang.Klingon,flip.*"

    --all               Run all probes (overrides --probes)

    --compare           Mode B: Basic + comparison matrix (MD + CSV)

    --full              Mode C: Compare + timing, cost estimates, summary

    --dry-run           Show what would run without executing

    --config-file FILE  Augustus YAML config file (default: configs/base.yaml)
                        Controls timeouts, concurrency, judge settings, etc.

    --env FILE          Path to env file (default: ~/.augustus-benchmark.env)

    --help              Show this help message

${BOLD}EXAMPLES${NC}
    # Basic scan with two providers
    $SCRIPT_NAME --providers "ollama:deepseek-r1:14b,openai:gpt-4o" --probes "dan.*"

    # Comparison mode with three providers
    $SCRIPT_NAME --providers "ollama:deepseek-r1:14b,openai:gpt-4o,anthropic:claude-sonnet-4-20250514" \\
                 --probes "dan.*,encoding.*" --compare

    # Full report with cost estimates and timing
    $SCRIPT_NAME --providers "ollama:deepseek-r1:14b,openai:gpt-4o" --probes "dan.*" --full

    # Run with buffs (adversarial transformations)
    $SCRIPT_NAME --providers "ollama:deepseek-r1:8b" --probes "dan.*" \\
                 --buffs "poetry.MetaPrompt,conlang.Klingon,flip.*"

    # Custom config with longer timeouts
    $SCRIPT_NAME --providers "openai:gpt-4o" --all --config-file configs/custom.yaml

    # Dry run to preview commands
    $SCRIPT_NAME --providers "openai:gpt-4o" --all --dry-run

${BOLD}PROVIDER FORMAT${NC}
    alias:model  ->  generator_class (resolved automatically)
      ollama:deepseek-r1:14b  ->  ollama.OllamaChat
      openai:gpt-4o           ->  openai.OpenAI
      anthropic:claude-sonnet-4-20250514  ->  anthropic.Anthropic

    Fully qualified generator names are also accepted:
      openai.OpenAI:gpt-4o

${BOLD}CONFIG FILE${NC}
    The default config (configs/base.yaml) sets scan timeouts, concurrency,
    and judge settings. Copy and customize it for your needs:
      cp configs/base.yaml configs/my-config.yaml
      # Edit timeouts, judge model, etc.
      $SCRIPT_NAME --providers "openai:gpt-4o" --probes "dan.*" --config-file configs/my-config.yaml

${BOLD}OUTPUT${NC}
    Results are saved to: benchmark-results/<YYYY-MM-DD-HHMMSS>/
EOF
    exit "${1:-0}"
}

# -- Argument parsing ---------------------------------------------------------

if [[ $# -eq 0 ]]; then
    usage 0
fi

while [[ $# -gt 0 ]]; do
    case "$1" in
        --providers)
            PROVIDERS="$2"
            shift 2
            ;;
        --probes)
            PROBES="$2"
            shift 2
            ;;
        --buffs)
            BUFFS="$2"
            shift 2
            ;;
        --all)
            ALL_PROBES=true
            shift
            ;;
        --compare)
            MODE="compare"
            shift
            ;;
        --full)
            MODE="full"
            shift
            ;;
        --dry-run)
            DRY_RUN=true
            shift
            ;;
        --config-file)
            CONFIG_FILE="$2"
            shift 2
            ;;
        --env)
            ENV_FILE="$2"
            shift 2
            ;;
        --help|-h)
            usage 0
            ;;
        *)
            log_error "Unknown option: $1"
            usage 1
            ;;
    esac
done

# -- Validation ---------------------------------------------------------------

if [[ -z "$PROVIDERS" ]]; then
    log_error "--providers is required"
    usage 1
fi

if [[ "$ALL_PROBES" == "false" && -z "$PROBES" ]]; then
    log_error "Either --probes or --all is required"
    usage 1
fi

if [[ ! -f "$CONFIG_FILE" ]]; then
    log_warn "Config file not found: $CONFIG_FILE (scan will use Augustus defaults)"
    CONFIG_FILE=""
fi

# -- Dependency check ---------------------------------------------------------

check_dependencies() {
    local -a missing_deps=()
    local -a required=("jq")

    for cmd in "${required[@]}"; do
        if ! command -v "$cmd" &>/dev/null; then
            missing_deps+=("$cmd")
        fi
    done

    if ! command -v augustus &>/dev/null; then
        missing_deps+=("augustus")
    fi

    if [[ ${#missing_deps[@]} -gt 0 ]]; then
        log_error "Missing required commands: ${missing_deps[*]}"
        log_error "Install them and try again."
        return 1
    fi
}

# -- Load environment ---------------------------------------------------------

load_env() {
    if [[ -f "$ENV_FILE" ]]; then
        log_info "Loading environment from: $ENV_FILE"
        # shellcheck disable=SC1090
        source "$ENV_FILE"
    else
        log_warn "Environment file not found: $ENV_FILE (API keys must be set in environment)"
    fi
}

# -- Parse provider string ----------------------------------------------------
# Input:  "ollama:deepseek-r1:14b,openai:gpt-4o"
# Output: Array of "generator|model|safe_name" entries

declare -a PARSED_PROVIDERS=()

parse_providers() {
    local provider_str="$1"
    local IFS=','

    for entry in $provider_str; do
        # Trim whitespace
        entry="$(echo "$entry" | xargs)"

        # Split on first colon: alias:model (model may contain colons, e.g. deepseek-r1:14b)
        local alias="${entry%%:*}"
        local model="${entry#*:}"

        if [[ "$alias" == "$model" ]]; then
            log_error "Invalid provider format: '$entry' (expected alias:model)"
            return 1
        fi

        local generator
        generator="$(resolve_generator "$alias")"

        # Create a filesystem-safe name for output files
        local safe_name
        safe_name="$(echo "${alias}_${model}" | tr ':/.,' '____' | tr '[:upper:]' '[:lower:]')"

        PARSED_PROVIDERS+=("${generator}|${model}|${safe_name}")
    done

    if [[ ${#PARSED_PROVIDERS[@]} -eq 0 ]]; then
        log_error "No providers parsed from: $provider_str"
        return 1
    fi
}

# -- Build probe arguments ----------------------------------------------------

build_probe_args() {
    if [[ "$ALL_PROBES" == "true" ]]; then
        echo "--all"
        return
    fi

    echo "--probes-glob \"${PROBES}\""
}

# -- Build buff arguments -----------------------------------------------------

build_buff_args() {
    if [[ -z "$BUFFS" ]]; then
        echo ""
        return
    fi

    echo "--buffs-glob \"${BUFFS}\""
}

# -- Build config arguments ---------------------------------------------------

build_config_args() {
    local model="$1"
    local args=""

    # YAML config file for scan settings (timeouts, judge, etc.)
    # NOTE: --config-file and --config are mutually exclusive in the CLI
    if [[ -n "$CONFIG_FILE" ]]; then
        args="--config-file \"${CONFIG_FILE}\""
    else
        # Inline JSON config for generator-specific model selection
        args="--config '{\"model\":\"${model}\"}'"
    fi

    echo "$args"
}

# -- Run a single provider scan -----------------------------------------------

run_scan() {
    local generator="$1"
    local model="$2"
    local safe_name="$3"
    local output_dir="$4"
    local probe_args="$5"
    local buff_args="$6"
    local index="$7"
    local total="$8"

    local jsonl_file="${output_dir}/${safe_name}.jsonl"
    local html_file="${output_dir}/${safe_name}.html"

    local config_args
    config_args="$(build_config_args "$model")"

    local cmd="augustus scan ${generator} ${probe_args} ${buff_args} ${config_args} --output \"${jsonl_file}\" --html \"${html_file}\""

    log_step "Scanning provider ${index}/${total}: ${generator} (${model})..."

    if [[ "$DRY_RUN" == "true" ]]; then
        printf "${YELLOW}[DRY RUN]${NC} Would execute:\n" >&2
        printf "  %s\n" "$cmd" >&2
        # Create empty placeholder files for dry run
        echo '{"probe":"example.Probe","detector":"example.Detector","score":0.5,"status":"vulnerable"}' > "$jsonl_file"
        return 0
    fi

    # Execute the scan, capturing timing if in full mode
    local start_time end_time duration
    start_time="$(date +%s)"

    # Run the actual scan command; continue on failure
    local scan_failed=false
    if eval "$cmd"; then
        log_info "Scan completed for: ${generator} (${model})"
    else
        log_warn "Scan FAILED for: ${generator} (${model}) - continuing with other providers"
        echo "{\"error\": true, \"provider\": \"${generator}\", \"model\": \"${model}\"}" > "$jsonl_file"
        scan_failed=true
    fi

    end_time="$(date +%s)"
    duration=$(( end_time - start_time ))

    # Write timing file for full mode
    if [[ "$MODE" == "full" ]]; then
        cat > "${output_dir}/${safe_name}.timing" <<TIMING_EOF
start=${start_time}
end=${end_time}
duration=${duration}
generator=${generator}
model=${model}
TIMING_EOF
    fi

    # Return non-zero so the caller can track failed providers
    if [[ "$scan_failed" == "true" ]]; then
        return 1
    fi
}

# -- Parse JSONL results to extract scores ------------------------------------

parse_jsonl_scores() {
    local jsonl_file="$1"

    if [[ ! -f "$jsonl_file" ]]; then
        log_warn "JSONL file not found: $jsonl_file"
        return 1
    fi

    jq -r 'select(.probe != null and .score != null) | "\(.probe)\t\(.score)\t\(.status // "unknown")"' "$jsonl_file" 2>/dev/null || true
}

# Get unique probe categories from a JSONL file
get_categories() {
    local jsonl_file="$1"
    jq -r 'select(.probe != null) | .probe | split(".")[0]' "$jsonl_file" 2>/dev/null | sort -u || true
}

# Compute average score for a category in a JSONL file
category_avg_score() {
    local jsonl_file="$1"
    local category="$2"

    jq -r --arg cat "$category" '
        select(.probe != null and .score != null and (.probe | startswith($cat + ".")))
        | .score
    ' "$jsonl_file" 2>/dev/null \
    | awk '{ sum += $1; count++ } END { if (count > 0) printf "%.3f", sum/count; else print "N/A" }'
}

# -- Generate comparison matrix -----------------------------------------------

generate_comparison() {
    local output_dir="$1"
    shift
    local -a providers=("$@")

    local md_file="${output_dir}/comparison.md"
    local csv_file="${output_dir}/comparison.csv"

    log_step "Generating comparison matrix..."

    # Collect all categories across all providers
    local -a all_categories=()
    for provider_entry in "${providers[@]}"; do
        IFS='|' read -r generator model safe_name <<< "$provider_entry"
        local jsonl_file="${output_dir}/${safe_name}.jsonl"
        if [[ -f "$jsonl_file" ]]; then
            while IFS= read -r cat; do
                [[ -n "$cat" ]] && all_categories+=("$cat")
            done < <(get_categories "$jsonl_file")
        fi
    done

    # Deduplicate and sort categories
    local -a unique_categories=()
    while IFS= read -r cat_line; do
        [[ -n "$cat_line" ]] && unique_categories+=("$cat_line")
    done < <(printf '%s\n' "${all_categories[@]}" | sort -u)

    if [[ ${#unique_categories[@]} -eq 0 ]]; then
        log_warn "No probe categories found in results - skipping comparison"
        return 0
    fi

    # -- Build Markdown table --

    # Header row
    local header="| Category |"
    local separator="|----------|"
    for provider_entry in "${providers[@]}"; do
        IFS='|' read -r generator model safe_name <<< "$provider_entry"
        header="${header} ${model} |"
        separator="${separator}--------|"
    done

    {
        echo "# Augustus Benchmark Comparison"
        echo ""
        echo "**Generated:** $(date '+%Y-%m-%d %H:%M:%S')"
        echo ""
        echo "**Probes:** ${PROBES:-all}"
        if [[ -n "$BUFFS" ]]; then
            echo "**Buffs:** ${BUFFS}"
        fi
        if [[ -n "$CONFIG_FILE" ]]; then
            echo "**Config:** $(basename "$CONFIG_FILE")"
        fi
        echo ""
        echo "## Vulnerability Scores by Category"
        echo ""
        echo "Scores range from 0.0 (safe) to 1.0 (vulnerable)."
        echo ""
        echo "$header"
        echo "$separator"
    } > "$md_file"

    # CSV header
    {
        printf "category"
        for provider_entry in "${providers[@]}"; do
            IFS='|' read -r generator model safe_name <<< "$provider_entry"
            printf ",%s" "$model"
        done
        printf "\n"
    } > "$csv_file"

    # Data rows
    for category in "${unique_categories[@]}"; do
        local md_row="| ${category} |"
        local csv_row="${category}"

        for provider_entry in "${providers[@]}"; do
            IFS='|' read -r generator model safe_name <<< "$provider_entry"
            local jsonl_file="${output_dir}/${safe_name}.jsonl"

            local score
            if [[ -f "$jsonl_file" ]]; then
                score="$(category_avg_score "$jsonl_file" "$category")"
            else
                score="N/A"
            fi

            md_row="${md_row} ${score} |"
            csv_row="${csv_row},${score}"
        done

        echo "$md_row" >> "$md_file"
        echo "$csv_row" >> "$csv_file"
    done

    # Append overall averages row
    local md_overall="| **Overall** |"
    local csv_overall="overall"
    for provider_entry in "${providers[@]}"; do
        IFS='|' read -r generator model safe_name <<< "$provider_entry"
        local jsonl_file="${output_dir}/${safe_name}.jsonl"

        local overall
        if [[ -f "$jsonl_file" ]]; then
            overall="$(jq -r 'select(.score != null) | .score' "$jsonl_file" 2>/dev/null \
                | awk '{ sum += $1; count++ } END { if (count > 0) printf "%.3f", sum/count; else print "N/A" }')"
        else
            overall="N/A"
        fi

        md_overall="${md_overall} **${overall}** |"
        csv_overall="${csv_overall},${overall}"
    done

    echo "$md_overall" >> "$md_file"
    echo "$csv_overall" >> "$csv_file"

    log_info "Comparison matrix written to:"
    log_info "  Markdown: ${md_file}"
    log_info "  CSV:      ${csv_file}"
}

# -- Generate full summary report ---------------------------------------------

generate_summary() {
    local output_dir="$1"
    shift
    local -a providers=("$@")

    local summary_file="${output_dir}/summary.md"

    log_step "Generating executive summary..."

    {
        echo "# Augustus Benchmark - Executive Summary"
        echo ""
        echo "**Date:** $(date '+%Y-%m-%d %H:%M:%S')"
        echo "**Probes:** ${PROBES:-all}"
        if [[ -n "$BUFFS" ]]; then
            echo "**Buffs:** ${BUFFS}"
        fi
        if [[ -n "$CONFIG_FILE" ]]; then
            echo "**Config:** $(basename "$CONFIG_FILE")"
        fi
        echo "**Mode:** Full analysis"
        echo ""
        echo "---"
        echo ""
        echo "## Provider Results"
        echo ""
    } > "$summary_file"

    for provider_entry in "${providers[@]}"; do
        IFS='|' read -r generator model safe_name <<< "$provider_entry"

        local jsonl_file="${output_dir}/${safe_name}.jsonl"
        local timing_file="${output_dir}/${safe_name}.timing"

        {
            echo "### ${generator} (${model})"
            echo ""
        } >> "$summary_file"

        # Timing information
        if [[ -f "$timing_file" ]]; then
            # shellcheck disable=SC1090
            source "$timing_file"
            local start_fmt end_fmt
            # macOS and GNU date differ; handle both
            if date --version &>/dev/null 2>&1; then
                start_fmt="$(date -d "@${start}" '+%H:%M:%S' 2>/dev/null || echo "$start")"
                end_fmt="$(date -d "@${end}" '+%H:%M:%S' 2>/dev/null || echo "$end")"
            else
                start_fmt="$(date -r "${start}" '+%H:%M:%S' 2>/dev/null || echo "$start")"
                end_fmt="$(date -r "${end}" '+%H:%M:%S' 2>/dev/null || echo "$end")"
            fi

            local mins=$(( duration / 60 ))
            local secs=$(( duration % 60 ))

            {
                echo "- **Start:** ${start_fmt}"
                echo "- **End:** ${end_fmt}"
                echo "- **Duration:** ${mins}m ${secs}s"
            } >> "$summary_file"
        fi

        # Score summary
        if [[ -f "$jsonl_file" ]]; then
            local total_probes vulnerable_probes overall_score
            total_probes="$(jq -r 'select(.probe != null) | .probe' "$jsonl_file" 2>/dev/null | wc -l | tr -d ' ')"
            vulnerable_probes="$(jq -r 'select(.status == "vulnerable") | .probe' "$jsonl_file" 2>/dev/null | wc -l | tr -d ' ')"
            overall_score="$(jq -r 'select(.score != null) | .score' "$jsonl_file" 2>/dev/null \
                | awk '{ sum += $1; count++ } END { if (count > 0) printf "%.3f", sum/count; else print "N/A" }')"

            {
                echo "- **Total probes:** ${total_probes}"
                echo "- **Vulnerable:** ${vulnerable_probes}"
                echo "- **Overall score:** ${overall_score}"
            } >> "$summary_file"

            # Cost estimate
            local cost_per_million
            cost_per_million="$(get_cost_per_million "$model")"
            if [[ -n "$cost_per_million" ]]; then
                # Rough token estimate: ~500 tokens per probe (input + output)
                local estimated_tokens=$(( total_probes * 500 ))
                local estimated_cost
                estimated_cost="$(awk -v tokens="$estimated_tokens" -v rate="$cost_per_million" \
                    'BEGIN { printf "%.4f", (tokens / 1000000) * rate }')"
                {
                    echo "- **Estimated tokens:** ~${estimated_tokens}"
                    echo "- **Estimated cost:** ~\$${estimated_cost} (at \$${cost_per_million}/1M input tokens)"
                } >> "$summary_file"
            else
                echo "- **Estimated cost:** N/A (pricing unknown for ${model})" >> "$summary_file"
            fi
        else
            echo "- **Status:** FAILED - no results" >> "$summary_file"
        fi

        echo "" >> "$summary_file"
    done

    # Recommendation section
    {
        echo "---"
        echo ""
        echo "## Key Findings"
        echo ""
        echo "*(Review the comparison matrix in \`comparison.md\` for detailed per-category scores.)*"
        echo ""
        echo "### Most Resilient Provider"
        echo ""
    } >> "$summary_file"

    # Find provider with lowest overall score (most resilient)
    local best_model="" best_score="999"
    for provider_entry in "${providers[@]}"; do
        IFS='|' read -r generator model safe_name <<< "$provider_entry"
        local jsonl_file="${output_dir}/${safe_name}.jsonl"

        if [[ -f "$jsonl_file" ]]; then
            local score
            score="$(jq -r 'select(.score != null) | .score' "$jsonl_file" 2>/dev/null \
                | awk '{ sum += $1; count++ } END { if (count > 0) printf "%.3f", sum/count; else print "999" }')"

            if awk -v a="$score" -v b="$best_score" 'BEGIN { exit !(a < b) }'; then
                best_score="$score"
                best_model="$model"
            fi
        fi
    done

    if [[ -n "$best_model" && "$best_score" != "999" ]]; then
        echo "**${best_model}** with an overall vulnerability score of **${best_score}**" >> "$summary_file"
    else
        echo "Unable to determine - review results manually." >> "$summary_file"
    fi

    # Find most vulnerable
    {
        echo ""
        echo "### Most Vulnerable Provider"
        echo ""
    } >> "$summary_file"

    local worst_model="" worst_score="-1"
    for provider_entry in "${providers[@]}"; do
        IFS='|' read -r generator model safe_name <<< "$provider_entry"
        local jsonl_file="${output_dir}/${safe_name}.jsonl"

        if [[ -f "$jsonl_file" ]]; then
            local score
            score="$(jq -r 'select(.score != null) | .score' "$jsonl_file" 2>/dev/null \
                | awk '{ sum += $1; count++ } END { if (count > 0) printf "%.3f", sum/count; else print "-1" }')"

            if awk -v a="$score" -v b="$worst_score" 'BEGIN { exit !(a > b) }'; then
                worst_score="$score"
                worst_model="$model"
            fi
        fi
    done

    if [[ -n "$worst_model" && "$worst_score" != "-1" ]]; then
        echo "**${worst_model}** with an overall vulnerability score of **${worst_score}**" >> "$summary_file"
    else
        echo "Unable to determine - review results manually." >> "$summary_file"
    fi

    echo "" >> "$summary_file"

    log_info "Executive summary written to: ${summary_file}"
}

# -- Main execution -----------------------------------------------------------

main() {
    log_bold "=========================================="
    log_bold "  Augustus Benchmark Runner"
    log_bold "=========================================="
    echo "" >&2

    # Check dependencies (skip in dry-run if augustus not installed)
    if [[ "$DRY_RUN" == "false" ]]; then
        check_dependencies
    else
        log_info "Dry-run mode - skipping dependency check"
    fi

    # Load environment
    load_env

    # Parse providers
    parse_providers "$PROVIDERS"
    local total_providers="${#PARSED_PROVIDERS[@]}"
    log_info "Providers: ${total_providers}"

    # Build probe arguments
    local probe_args
    probe_args="$(build_probe_args)"
    if [[ "$ALL_PROBES" == "true" ]]; then
        log_info "Probes: ALL"
    else
        log_info "Probes: ${PROBES}"
    fi

    # Build buff arguments
    local buff_args
    buff_args="$(build_buff_args)"
    if [[ -n "$BUFFS" ]]; then
        log_info "Buffs: ${BUFFS}"
    fi

    if [[ -n "$CONFIG_FILE" ]]; then
        log_info "Config: ${CONFIG_FILE}"
    fi
    log_info "Mode: ${MODE}"

    # Create output directory
    local timestamp
    timestamp="$(date '+%Y-%m-%d-%H%M%S')"
    local output_dir="${WORKSPACE_DIR}/benchmark-results/${timestamp}"
    mkdir -p "$output_dir"
    log_info "Output directory: ${output_dir}"

    # Copy config file to output directory for reproducibility
    if [[ -n "$CONFIG_FILE" && -f "$CONFIG_FILE" ]]; then
        cp "$CONFIG_FILE" "${output_dir}/config.yaml"
    fi

    echo "" >&2

    # -- Mode A: Run scans per provider --

    local index=0
    local -a failed_providers=()

    for provider_entry in "${PARSED_PROVIDERS[@]}"; do
        index=$(( index + 1 ))
        IFS='|' read -r generator model safe_name <<< "$provider_entry"

        if ! run_scan "$generator" "$model" "$safe_name" "$output_dir" "$probe_args" "$buff_args" "$index" "$total_providers"; then
            failed_providers+=("${generator}:${model}")
        fi

        echo "" >&2
    done

    # Report failures
    if [[ ${#failed_providers[@]} -gt 0 ]]; then
        log_warn "The following providers failed:"
        for fp in "${failed_providers[@]}"; do
            log_warn "  - ${fp}"
        done
        echo "" >&2
    fi

    # -- Mode B: Generate comparison --

    if [[ "$MODE" == "compare" || "$MODE" == "full" ]]; then
        generate_comparison "$output_dir" "${PARSED_PROVIDERS[@]}"
        echo "" >&2
    fi

    # -- Mode C: Generate full summary --

    if [[ "$MODE" == "full" ]]; then
        generate_summary "$output_dir" "${PARSED_PROVIDERS[@]}"
        echo "" >&2
    fi

    # -- Final report --

    log_bold "=========================================="
    log_bold "  Benchmark Complete"
    log_bold "=========================================="
    echo "" >&2
    log_info "Results saved to: ${output_dir}/"
    echo "" >&2

    # List output files
    log_info "Output files:"
    for f in "$output_dir"/*; do
        if [[ -f "$f" ]]; then
            local size
            size="$(wc -c < "$f" | tr -d ' ')"
            log_info "  $(basename "$f") (${size} bytes)"
        fi
    done

    if [[ ${#failed_providers[@]} -gt 0 ]]; then
        echo "" >&2
        log_warn "${#failed_providers[@]} provider(s) failed - check individual JSONL files for details"
    fi
}

main
