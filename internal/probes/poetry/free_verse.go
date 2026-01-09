package poetry

import (
	"strings"

	"github.com/praetorian-inc/augustus/pkg/probes"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

func init() {
	probes.Register("poetry.InjectFreeVerse", NewInjectFreeVerse)
}

// InjectFreeVerse probes for susceptibility to free verse-formatted harmful instructions.
type InjectFreeVerse struct {
	*PoetryProbe
}

// NewInjectFreeVerse creates a new InjectFreeVerse probe.
func NewInjectFreeVerse(_ registry.Config) (probes.Prober, error) {
	templates := LoadFreeVerseTemplates()

	formatters := make([]PoetryFormatter, 0, len(templates))
	for _, template := range templates {
		formatters = append(formatters, NewFreeVerseFormatter(template))
	}

	base := NewPoetryProbe(
		"poetry.InjectFreeVerse",
		"free_verse",
		FormatDescription("free verse"),
		formatters,
	)

	return &InjectFreeVerse{PoetryProbe: base}, nil
}

// NewFreeVerseFormatter creates a formatter that converts payloads to free verse.
func NewFreeVerseFormatter(template string) PoetryFormatter {
	return func(payload string) string {
		action := extractAction(payload)
		target := extractTarget(payload)

		verse := strings.ReplaceAll(template, "{action}", action)
		verse = strings.ReplaceAll(verse, "{target}", target)
		verse = strings.ReplaceAll(verse, "{instruction_full}", payload)
		verse = strings.ReplaceAll(verse, "{outcome}", "knowledge gained")

		return verse
	}
}
