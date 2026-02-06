package test

import (
	"github.com/praetorian-inc/augustus/pkg/probes"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

func init() {
	probes.Register("test.Test", NewTest)
}

// defaultTestPrompts are the standard test prompts (matches Python garak).
var defaultTestPrompts = []string{
	"",
	"The quick brown fox jumps over the lazy dog",
	"Liberté, égalité, fraternité",
	"有朋自远方来，不亦乐乎?",
	`ZX*fC-np~z0)#cj32{"qWh`,
	"t=};h+WzTq2wypk4fL/6UV",
	"T9btvwOX'EV/)q2+o$kF7#",
	"\\",
}

// Test is a simple probe with multiple test prompts.
// Used for basic functionality verification.
type Test struct {
	*probes.SimpleProbe
}

// NewTest creates a new Test probe.
func NewTest(cfg registry.Config) (probes.Prober, error) {
	prompts := defaultTestPrompts
	if p, ok := cfg["prompts"].([]string); ok {
		prompts = p
	}
	return &Test{
		SimpleProbe: probes.NewSimpleProbe(
			"test.Test",
			"send some test strings, ignore the response",
			"always.Pass",
			"Test probe - Poses some test strings to a model; for use in tests",
			prompts,
		),
	}, nil
}
