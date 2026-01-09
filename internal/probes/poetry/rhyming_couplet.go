package poetry

import (
	"strings"

	"github.com/praetorian-inc/augustus/pkg/probes"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

func init() {
	probes.Register("poetry.InjectRhymingCouplet", NewInjectRhymingCouplet)
}

// InjectRhymingCouplet probes for susceptibility to rhyming couplet-formatted harmful instructions.
type InjectRhymingCouplet struct {
	*PoetryProbe
}

// NewInjectRhymingCouplet creates a new InjectRhymingCouplet probe.
func NewInjectRhymingCouplet(_ registry.Config) (probes.Prober, error) {
	templates := LoadRhymingCoupletTemplates()

	formatters := make([]PoetryFormatter, 0, len(templates))
	for _, template := range templates {
		formatters = append(formatters, NewRhymingCoupletFormatter(template))
	}

	base := NewPoetryProbe(
		"poetry.InjectRhymingCouplet",
		"rhyming_couplet",
		FormatDescription("rhyming couplet"),
		formatters,
	)

	return &InjectRhymingCouplet{PoetryProbe: base}, nil
}

// NewRhymingCoupletFormatter creates a formatter that converts payloads to rhyming couplets.
func NewRhymingCoupletFormatter(template string) PoetryFormatter {
	return func(payload string) string {
		action := extractAction(payload)
		target := extractTarget(payload)
		instruction := simplifyInstruction(payload)

		couplet := strings.ReplaceAll(template, "{action}", action)
		couplet = strings.ReplaceAll(couplet, "{target}", target)
		couplet = strings.ReplaceAll(couplet, "{instruction_line1}", instruction)
		couplet = strings.ReplaceAll(couplet, "{instruction_line2}", "Follow these steps")

		return couplet
	}
}
