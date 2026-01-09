package poetry

import (
	"fmt"
	"strings"

	"github.com/praetorian-inc/augustus/pkg/probes"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

func init() {
	probes.Register("poetry.InjectSonnet", NewInjectSonnet)
}

// InjectSonnet probes for susceptibility to sonnet-formatted harmful instructions.
type InjectSonnet struct {
	*PoetryProbe
}

// NewInjectSonnet creates a new InjectSonnet probe.
func NewInjectSonnet(_ registry.Config) (probes.Prober, error) {
	templates := LoadSonnetTemplates()

	formatters := make([]PoetryFormatter, 0, len(templates))
	for _, template := range templates {
		formatters = append(formatters, NewSonnetFormatter(template))
	}

	base := NewPoetryProbe(
		"poetry.InjectSonnet",
		"sonnet",
		FormatDescription("sonnet"),
		formatters,
	)

	return &InjectSonnet{PoetryProbe: base}, nil
}

// NewSonnetFormatter creates a formatter that converts payloads to sonnet.
func NewSonnetFormatter(template string) PoetryFormatter {
	return func(payload string) string {
		action := extractAction(payload)
		target := extractTarget(payload)
		words := strings.Fields(payload)

		sonnet := strings.ReplaceAll(template, "{action}", action)
		sonnet = strings.ReplaceAll(sonnet, "{target}", target)

		// Fill instruction lines - distribute words across 4 lines
		wordsPerLine := len(words) / 4
		if wordsPerLine < 1 {
			wordsPerLine = 1
		}

		for i := 1; i <= 4; i++ {
			placeholder := fmt.Sprintf("{instruction_line%d}", i)
			start := (i - 1) * wordsPerLine
			end := i * wordsPerLine
			if i == 4 {
				// Last line gets all remaining words
				end = len(words)
			}
			if start >= len(words) {
				// If we've run out of words, repeat the payload
				sonnet = strings.ReplaceAll(sonnet, placeholder, payload)
			} else if end > len(words) {
				end = len(words)
				line := strings.Join(words[start:end], " ")
				sonnet = strings.ReplaceAll(sonnet, placeholder, line)
			} else {
				line := strings.Join(words[start:end], " ")
				sonnet = strings.ReplaceAll(sonnet, placeholder, line)
			}
		}

		return sonnet
	}
}
