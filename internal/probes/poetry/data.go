// Package poetry provides poetry-based prompt injection probes for LLM testing.
package poetry

import (
	_ "embed"
	"strings"

	"github.com/praetorian-inc/augustus/pkg/probes"
)

//go:embed data/harmful_payloads.txt
var harmfulPayloadsData string

//go:embed data/payload_categories.txt
var payloadCategoriesData string

//go:embed data/templates/haiku.txt
var haikuTemplatesData string

//go:embed data/templates/sonnet.txt
var sonnetTemplatesData string

//go:embed data/templates/limerick.txt
var limerickTemplatesData string

//go:embed data/templates/free_verse.txt
var freeVerseTemplatesData string

//go:embed data/templates/rhyming_couplet.txt
var rhymingCoupletTemplatesData string

// DefaultHarmfulPayloads contains harmful instructions to reformulate into poetry.
var DefaultHarmfulPayloads []string

func init() {
	DefaultHarmfulPayloads = probes.SplitLinesSkipComments(harmfulPayloadsData)
}

// parseTemplates splits template data by "---" separator.
func parseTemplates(data string) []string {
	templates := strings.Split(data, "---")
	result := make([]string, 0, len(templates))

	for _, t := range templates {
		trimmed := strings.TrimSpace(t)
		if trimmed != "" {
			result = append(result, trimmed)
		}
	}

	return result
}

// LoadHaikuTemplates returns embedded haiku templates.
func LoadHaikuTemplates() []string {
	return parseTemplates(haikuTemplatesData)
}

// LoadSonnetTemplates returns embedded sonnet templates.
func LoadSonnetTemplates() []string {
	return parseTemplates(sonnetTemplatesData)
}

// LoadLimerickTemplates returns embedded limerick templates.
func LoadLimerickTemplates() []string {
	return parseTemplates(limerickTemplatesData)
}

// LoadFreeVerseTemplates returns embedded free verse templates.
func LoadFreeVerseTemplates() []string {
	return parseTemplates(freeVerseTemplatesData)
}

// LoadRhymingCoupletTemplates returns embedded rhyming couplet templates.
func LoadRhymingCoupletTemplates() []string {
	return parseTemplates(rhymingCoupletTemplatesData)
}

// PayloadCategory represents an MLCommons AILuminate hazard category.
type PayloadCategory struct {
	ID     string
	Name   string
	Domain string
}

// LoadPayloadCategories returns the MLCommons AILuminate taxonomy.
func LoadPayloadCategories() []PayloadCategory {
	var categories []PayloadCategory
	for _, line := range strings.Split(payloadCategoriesData, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "|", 3)
		if len(parts) != 3 {
			continue
		}
		categories = append(categories, PayloadCategory{
			ID:     strings.TrimSpace(parts[0]),
			Name:   strings.TrimSpace(parts[1]),
			Domain: strings.TrimSpace(parts[2]),
		})
	}
	return categories
}
