package probes

import (
	"context"

	"github.com/praetorian-inc/augustus/pkg/attempt"
)

// SimpleProbe provides shared infrastructure for probes that iterate over a
// static list of prompts, sending each one to the generator and collecting
// attempts. It implements the full Prober interface.
//
// Embed this struct by pointer (*SimpleProbe) in domain-specific probe types
// to eliminate boilerplate. For probes that need per-attempt metadata (e.g.
// trigger tokens), set the MetadataFn callback.
type SimpleProbe struct {
	ProbeName       string
	ProbeGoal       string
	PrimaryDetector string
	ProbeDescription string
	Prompts         []string

	// MetadataFn is an optional callback invoked for each attempt after it is
	// created but before outputs are added. The index corresponds to the
	// position of the prompt in Prompts. Use this to attach per-attempt
	// metadata such as trigger tokens.
	MetadataFn func(i int, prompt string, a *attempt.Attempt)
}

// NewSimpleProbe creates a new SimpleProbe with the given configuration.
func NewSimpleProbe(name, goal, detector, description string, prompts []string) *SimpleProbe {
	return &SimpleProbe{
		ProbeName:        name,
		ProbeGoal:        goal,
		PrimaryDetector:  detector,
		ProbeDescription: description,
		Prompts:          prompts,
	}
}

// Probe executes the probe against the generator by iterating over all prompts.
// It checks for context cancellation between iterations.
func (s *SimpleProbe) Probe(ctx context.Context, gen Generator) ([]*attempt.Attempt, error) {
	return RunPrompts(ctx, gen, s.Prompts, s.Name(), s.GetPrimaryDetector(), s.MetadataFn)
}

// Name returns the probe's fully qualified name.
func (s *SimpleProbe) Name() string {
	return s.ProbeName
}

// Description returns a human-readable description.
func (s *SimpleProbe) Description() string {
	return s.ProbeDescription
}

// Goal returns the probe's goal.
func (s *SimpleProbe) Goal() string {
	return s.ProbeGoal
}

// GetPrimaryDetector returns the recommended detector.
func (s *SimpleProbe) GetPrimaryDetector() string {
	return s.PrimaryDetector
}

// GetPrompts returns the prompts used by this probe.
func (s *SimpleProbe) GetPrompts() []string {
	return s.Prompts
}
