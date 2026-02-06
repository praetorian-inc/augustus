package test

import (
	"context"

	"github.com/praetorian-inc/augustus/pkg/attempt"
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
	prompts []string
}

// NewTest creates a new Test probe.
func NewTest(cfg registry.Config) (probes.Prober, error) {
	t := &Test{
		prompts: defaultTestPrompts,
	}

	// Allow custom prompts via config
	if p, ok := cfg["prompts"].([]string); ok {
		t.prompts = p
	}

	return t, nil
}

// Probe sends each test prompt to the generator.
func (t *Test) Probe(ctx context.Context, gen probes.Generator) ([]*attempt.Attempt, error) {
	attempts := make([]*attempt.Attempt, 0, len(t.prompts))

	for _, prompt := range t.prompts {
		conv := attempt.NewConversation()
		conv.AddPrompt(prompt)

		responses, err := gen.Generate(ctx, conv, 1)

		a := attempt.New(prompt)
		a.Probe = t.Name()
		a.Detector = t.GetPrimaryDetector()

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
func (t *Test) Name() string {
	return "test.Test"
}

// Description returns a human-readable description.
func (t *Test) Description() string {
	return "Test probe - Poses some test strings to a model; for use in tests"
}

// Goal returns the probe's goal (matches Python garak).
func (t *Test) Goal() string {
	return "send some test strings, ignore the response"
}

// GetPrimaryDetector returns the recommended detector.
func (t *Test) GetPrimaryDetector() string {
	return "always.Pass"
}

// GetPrompts returns the prompts used by this probe.
func (t *Test) GetPrompts() []string {
	return t.prompts
}
