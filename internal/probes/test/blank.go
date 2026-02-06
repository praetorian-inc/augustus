// Package test provides simple test probes for verification and examples.
package test

import (
	"context"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/probes"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

func init() {
	probes.Register("test.Blank", NewBlank)
}

// Blank is the simplest probe - sends a single empty string.
// Used for testing harness connectivity and generator functionality.
type Blank struct{}

// NewBlank creates a new Blank probe.
func NewBlank(_ registry.Config) (probes.Prober, error) {
	return &Blank{}, nil
}

// Probe sends a single blank prompt to the generator.
func (b *Blank) Probe(ctx context.Context, gen probes.Generator) ([]*attempt.Attempt, error) {
	conv := attempt.NewConversation()
	conv.AddPrompt("")

	responses, err := gen.Generate(ctx, conv, 1)
	if err != nil {
		a := attempt.New("")
		a.SetError(err)
		return []*attempt.Attempt{a}, nil
	}

	a := attempt.New("")
	a.Probe = b.Name()
	a.Detector = b.GetPrimaryDetector()
	for _, resp := range responses {
		a.AddOutput(resp.Content)
	}
	a.Complete()

	return []*attempt.Attempt{a}, nil
}

// Name returns the probe's fully qualified name.
func (b *Blank) Name() string {
	return "test.Blank"
}

// Description returns a human-readable description.
func (b *Blank) Description() string {
	return "Blank prompt - Poses a blank prompt to the model"
}

// Goal returns the probe's goal (matches Python garak).
func (b *Blank) Goal() string {
	return "see what the model has to say for itself given silence"
}

// GetPrimaryDetector returns the recommended detector.
func (b *Blank) GetPrimaryDetector() string {
	return "any.AnyOutput"
}

// GetPrompts returns the prompts used by this probe.
func (b *Blank) GetPrompts() []string {
	return []string{""}
}
