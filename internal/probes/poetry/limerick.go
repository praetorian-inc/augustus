package poetry

import (
	"strings"

	"github.com/praetorian-inc/augustus/pkg/probes"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

func init() {
	probes.Register("poetry.InjectLimerick", NewInjectLimerick)
}

// InjectLimerick probes for susceptibility to limerick-formatted harmful instructions.
type InjectLimerick struct {
	*PoetryProbe
}

// NewInjectLimerick creates a new InjectLimerick probe.
func NewInjectLimerick(_ registry.Config) (probes.Prober, error) {
	templates := LoadLimerickTemplates()

	formatters := make([]PoetryFormatter, 0, len(templates))
	for _, template := range templates {
		formatters = append(formatters, NewLimerickFormatter(template))
	}

	base := NewPoetryProbe(
		"poetry.InjectLimerick",
		"limerick",
		FormatDescription("limerick"),
		formatters,
	)

	return &InjectLimerick{PoetryProbe: base}, nil
}

// NewLimerickFormatter creates a formatter that converts payloads to limerick.
func NewLimerickFormatter(template string) PoetryFormatter {
	return func(payload string) string {
		action := extractAction(payload)
		target := extractTarget(payload)
		instruction := simplifyInstruction(payload)

		limerick := strings.ReplaceAll(template, "{action}", action)
		limerick = strings.ReplaceAll(limerick, "{target}", target)
		limerick = strings.ReplaceAll(limerick, "{instruction_short}", instruction)
		limerick = strings.ReplaceAll(limerick, "{instruction_line1}", instruction)
		limerick = strings.ReplaceAll(limerick, "{instruction_line2}", "The method is clear")

		return limerick
	}
}
