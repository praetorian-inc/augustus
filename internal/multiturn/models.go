package multiturn

import (
	"bufio"
	_ "embed"
	"strconv"
	"strings"
)

// defaultContextTokenLimit is the fallback token limit when the model is unknown.
const defaultContextTokenLimit = 7500

//go:embed data/model_context_windows.yaml
var modelContextWindowsRaw string

// modelContextWindows maps model name prefixes to their context window sizes in tokens.
// Loaded from data/model_context_windows.yaml at init.
var modelContextWindows map[string]int

func init() {
	modelContextWindows = parseModelContextWindows(modelContextWindowsRaw)
}

// parseModelContextWindows parses the YAML-like "key: value" format into a map.
func parseModelContextWindows(data string) map[string]int {
	m := make(map[string]int)
	scanner := bufio.NewScanner(strings.NewReader(data))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			continue
		}
		key := strings.TrimSpace(parts[0])
		val, err := strconv.Atoi(strings.TrimSpace(parts[1]))
		if err != nil {
			continue
		}
		m[key] = val
	}
	return m
}

// contextTokenLimit returns the token limit for conversation trimming based on the model name.
// It uses prefix matching against modelContextWindows, falling back to defaultContextTokenLimit.
func contextTokenLimit(model string) int {
	if model == "" {
		return defaultContextTokenLimit
	}
	model = strings.ToLower(model)

	bestMatch := ""
	bestLimit := 0
	for prefix, limit := range modelContextWindows {
		if strings.HasPrefix(model, prefix) && len(prefix) > len(bestMatch) {
			bestMatch = prefix
			bestLimit = limit
		}
	}
	if bestMatch != "" {
		return bestLimit
	}

	return defaultContextTokenLimit
}

// ResponseCharBudget returns a per-response character budget derived from the
// attacker model's context window. Larger context models can afford to include
// more of the target's response, giving the attacker better signal.
func ResponseCharBudget(model string) int {
	tokens := contextTokenLimit(model)
	switch {
	case tokens >= 100_000:
		return 2000
	case tokens >= 30_000:
		return 1000
	case tokens >= 8_000:
		return 600
	default:
		return 300
	}
}
