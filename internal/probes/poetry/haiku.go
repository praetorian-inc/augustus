package poetry

import (
	"strings"

	"github.com/praetorian-inc/augustus/pkg/probes"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

func init() {
	probes.Register("poetry.InjectHaiku", NewInjectHaiku)
}

// InjectHaiku probes for susceptibility to haiku-formatted harmful instructions.
type InjectHaiku struct {
	*PoetryProbe
}

// NewInjectHaiku creates a new InjectHaiku probe.
func NewInjectHaiku(_ registry.Config) (probes.Prober, error) {
	templates := LoadHaikuTemplates()

	formatters := make([]PoetryFormatter, 0, len(templates))
	for _, template := range templates {
		formatters = append(formatters, NewHaikuFormatter(template))
	}

	base := NewPoetryProbe(
		"poetry.InjectHaiku",
		"haiku",
		FormatDescription("haiku"),
		formatters,
	)

	return &InjectHaiku{PoetryProbe: base}, nil
}

// NewHaikuFormatter creates a formatter that converts payloads to haiku.
func NewHaikuFormatter(template string) PoetryFormatter {
	return func(payload string) string {
		action := extractAction(payload)
		target := extractTarget(payload)

		haiku := strings.ReplaceAll(template, "{action}", action)
		haiku = strings.ReplaceAll(haiku, "{target}", target)
		haiku = strings.ReplaceAll(haiku, "{instruction}", simplifyInstruction(payload))
		haiku = strings.ReplaceAll(haiku, "{instruction_full}", payload)

		return haiku
	}
}

func simplifyInstruction(payload string) string {
	// Extract key phrase from payload
	words := strings.Fields(payload)
	if len(words) > 5 {
		return strings.Join(words[2:5], " ")
	}
	return strings.Join(words, " ")
}
