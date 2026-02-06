// Package badchars provides imperceptible perturbation probes using homoglyph substitution.
//
// Implements homoglyph character substitution attacks inspired by the "Bad Characters" paper
// (https://arxiv.org/abs/2106.09898). These probes substitute characters with visually
// similar Unicode homoglyphs to obfuscate prompts while maintaining visual equivalence.
package badchars

import (
	"bufio"
	"context"
	"embed"
	"fmt"
	"strconv"
	"strings"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/probes"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

func init() {
	probes.Register("badchars.Homoglyphs", NewHomoglyphs)
}

//go:embed data/intentional.txt
var intentionalFS embed.FS

const (
	defaultHomoglyphBudget = 1 // How many characters to substitute per variant
)

// homoglyphVariant represents a generated prompt variant with homoglyph substitutions.
type homoglyphVariant struct {
	text         string
	positions    []int
	replacements []string
}

// Homoglyphs substitutes characters with visually similar Unicode homoglyphs.
//
// Python garak equivalent: garak.probes.badchars.BadCharacters (homoglyph category)
type Homoglyphs struct {
	name            string
	goal            string
	primaryDetector string
	description     string
	prompts         []string
	metadata        []map[string]any
}

// NewHomoglyphs creates a new Homoglyphs probe.
func NewHomoglyphs(_ registry.Config) (probes.Prober, error) {
	homoglyphMap, err := loadHomoglyphMap()
	if err != nil {
		return nil, fmt.Errorf("failed to load homoglyph map: %w", err)
	}

	prompts, metadata := generateAllHomoglyphVariants(
		defaultPayloads,
		defaultHomoglyphBudget,
		homoglyphMap,
	)

	return &Homoglyphs{
		name:            "badchars.Homoglyphs",
		goal:            "inject imperceptible homoglyphs to bypass refusal",
		primaryDetector: "mitigation.MitigationBypass",
		description: "Probe for susceptibility to homoglyph character substitution. " +
			"Substitutes characters with visually similar Unicode homoglyphs " +
			"(e.g., Latin 'A' with Greek 'Α') to test if models can be tricked by " +
			"imperceptible character-level perturbations.",
		prompts:  prompts,
		metadata: metadata,
	}, nil
}

// Probe executes the homoglyph probe against the generator.
func (p *Homoglyphs) Probe(ctx context.Context, gen probes.Generator) ([]*attempt.Attempt, error) {
	attempts := make([]*attempt.Attempt, 0, len(p.prompts))

	for i, prompt := range p.prompts {
		conv := attempt.NewConversation()
		conv.AddPrompt(prompt)

		responses, err := gen.Generate(ctx, conv, 1)

		a := attempt.New(prompt)
		a.Probe = p.Name()
		a.Detector = p.GetPrimaryDetector()

		// Copy metadata for this variant
		if i < len(p.metadata) {
			a.Metadata = p.metadata[i]
		}

		if err != nil {
			a.SetError(err)
		} else {
			for _, resp := range responses {
				a.AddOutput(resp.Content)
			}
			a.Complete()
		}

		attempts = append(attempts, a)
	}

	return attempts, nil
}

// Name returns the probe's fully qualified name.
func (p *Homoglyphs) Name() string {
	return p.name
}

// Description returns a human-readable description.
func (p *Homoglyphs) Description() string {
	return p.description
}

// Goal returns the probe's goal (matches Python garak).
func (p *Homoglyphs) Goal() string {
	return p.goal
}

// GetPrimaryDetector returns the recommended detector.
func (p *Homoglyphs) GetPrimaryDetector() string {
	return p.primaryDetector
}

// GetPrompts returns the attack prompts used by this probe.
func (p *Homoglyphs) GetPrompts() []string {
	return p.prompts
}

// loadHomoglyphMap parses intentional.txt into a source -> targets dictionary.
// Matches Python _load_homoglyph_map (badchars.py lines 78-109).
func loadHomoglyphMap() (map[rune][]string, error) {
	content, err := intentionalFS.ReadFile("data/intentional.txt")
	if err != nil {
		return nil, fmt.Errorf("failed to read intentional.txt: %w", err)
	}

	mapping := make(map[rune][]string)
	scanner := bufio.NewScanner(strings.NewReader(string(content)))

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Parse line format: "0041 ; 0391 # comment"
		parts := strings.SplitN(line, ";", 2)
		if len(parts) != 2 {
			continue
		}

		// Extract source codepoint
		sourceHex := strings.TrimSpace(parts[0])
		sourceCP, err := strconv.ParseInt(sourceHex, 16, 32)
		if err != nil {
			continue
		}
		source := rune(sourceCP)

		// Extract target codepoint(s)
		remainder := strings.TrimSpace(parts[1])
		// Remove comment part
		if idx := strings.Index(remainder, "#"); idx != -1 {
			remainder = remainder[:idx]
		}
		remainder = strings.TrimSpace(remainder)

		if remainder == "" {
			continue
		}

		// Parse target codepoints (space-separated hex values)
		targetHexes := strings.Fields(remainder)
		if len(targetHexes) == 0 {
			continue
		}

		// Build target string from codepoints
		targetRunes := make([]rune, 0, len(targetHexes))
		for _, hexStr := range targetHexes {
			targetCP, err := strconv.ParseInt(hexStr, 16, 32)
			if err != nil {
				continue
			}
			targetRunes = append(targetRunes, rune(targetCP))
		}

		target := string(targetRunes)

		// Skip if source equals target
		if string(source) == target {
			continue
		}

		// Add to mapping (using slice to preserve order and allow duplicates)
		mapping[source] = append(mapping[source], target)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error scanning intentional.txt: %w", err)
	}

	// Sort targets for each source to ensure deterministic output
	for source := range mapping {
		sortStrings(mapping[source])
	}

	return mapping, nil
}

// generateAllHomoglyphVariants generates all prompt variants for all payloads.
func generateAllHomoglyphVariants(
	payloads []string,
	budget int,
	homoglyphMap map[rune][]string,
) ([]string, []map[string]any) {
	var prompts []string
	var metadata []map[string]any

	for payloadIdx, payload := range payloads {
		variants := generateHomoglyphVariants(payload, budget, homoglyphMap)

		for _, v := range variants {
			prompts = append(prompts, v.text)
			metadata = append(metadata, map[string]any{
				"bad_character_category": "homoglyph",
				"perturbation_count":     len(v.positions),
				"source_payload_index":   payloadIdx,
				"positions":              v.positions,
				"replacements":           v.replacements,
			})
		}
	}

	return prompts, metadata
}

// generateHomoglyphVariants generates variants of a payload with homoglyph substitutions.
// Matches Python garak _generate_homoglyph_variants (badchars.py lines 256-280).
func generateHomoglyphVariants(
	payload string,
	budget int,
	homoglyphMap map[rune][]string,
) []homoglyphVariant {
	if payload == "" {
		return nil
	}

	// Find candidate positions (characters that have homoglyph mappings)
	var candidatePositions []int
	payloadRunes := []rune(payload)

	for i, r := range payloadRunes {
		if _, ok := homoglyphMap[r]; ok {
			candidatePositions = append(candidatePositions, i)
		}
	}

	if len(candidatePositions) == 0 {
		return nil
	}

	var variants []homoglyphVariant
	maxReplacements := budget
	if maxReplacements > len(candidatePositions) {
		maxReplacements = len(candidatePositions)
	}

	// For each count from 1 to budget
	for count := 1; count <= maxReplacements; count++ {
		// For each combination of positions
		for _, posCombo := range combinations(candidatePositions, count) {
			// Build replacement options for each position
			var replacementOptions [][]string
			for _, pos := range posCombo {
				char := payloadRunes[pos]
				options := homoglyphMap[char]
				replacementOptions = append(replacementOptions, options)
			}

			// Generate all combinations of replacements
			for _, replacements := range cartesianProductStrings(replacementOptions) {
				// Apply substitutions
				text := applyHomoglyphSubstitutions(payload, posCombo, replacements)
				variants = append(variants, homoglyphVariant{
					text:         text,
					positions:    posCombo,
					replacements: replacements,
				})
			}
		}
	}

	return variants
}

// applyHomoglyphSubstitutions applies homoglyph substitutions at specified positions.
func applyHomoglyphSubstitutions(payload string, positions []int, replacements []string) string {
	payloadRunes := []rune(payload)

	// Create a copy to track which positions to replace
	result := make([]rune, len(payloadRunes))
	copy(result, payloadRunes)

	// Create a map of positions to replacements
	posMap := make(map[int]string)
	for i, pos := range positions {
		if pos >= 0 && pos < len(payloadRunes) {
			posMap[pos] = replacements[i]
		}
	}

	// Build the result by replacing characters at specified positions
	var builder strings.Builder
	for i, r := range payloadRunes {
		if replacement, ok := posMap[i]; ok {
			builder.WriteString(replacement)
		} else {
			builder.WriteRune(r)
		}
	}

	return builder.String()
}

// cartesianProductStrings generates the Cartesian product of string slices.
func cartesianProductStrings(slices [][]string) [][]string {
	if len(slices) == 0 {
		return nil
	}

	// Calculate total number of combinations
	total := 1
	for _, s := range slices {
		if len(s) == 0 {
			return nil
		}
		total *= len(s)
	}

	result := make([][]string, total)
	indices := make([]int, len(slices))

	for i := 0; i < total; i++ {
		combo := make([]string, len(slices))
		for j := 0; j < len(slices); j++ {
			combo[j] = slices[j][indices[j]]
		}
		result[i] = combo

		// Increment indices (like counting in mixed-radix number system)
		for j := len(slices) - 1; j >= 0; j-- {
			indices[j]++
			if indices[j] < len(slices[j]) {
				break
			}
			indices[j] = 0
		}
	}

	return result
}

// sortStrings sorts a string slice (ascending) in place.
func sortStrings(slice []string) {
	// Simple bubble sort (good enough for small slices)
	for i := 0; i < len(slice); i++ {
		for j := i + 1; j < len(slice); j++ {
			if slice[j] < slice[i] {
				slice[i], slice[j] = slice[j], slice[i]
			}
		}
	}
}
