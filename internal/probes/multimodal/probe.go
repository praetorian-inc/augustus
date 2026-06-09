package multimodal

import (
	"context"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/types"
)

// BaseMultimodalProbe provides shared infrastructure for multimodal probes.
//
// Embed this struct by value in domain-specific multimodal probe types to
// eliminate boilerplate. It implements the full MultimodalProbe interface.
type BaseMultimodalProbe struct {
	ProbeName        string
	ProbeGoal        string
	PrimaryDetector  string
	ProbeDescription string
	Prompts          []MultimodalPrompt
}

// Probe executes the probe against the generator by iterating over all prompts.
func (p *BaseMultimodalProbe) Probe(ctx context.Context, gen types.Generator) ([]*attempt.Attempt, error) {
	return RunMultimodalPrompts(ctx, gen, p.Prompts, p.Name(), p.GetPrimaryDetector())
}

// Name returns the probe's fully qualified name.
func (p *BaseMultimodalProbe) Name() string {
	return p.ProbeName
}

// Description returns a human-readable description.
func (p *BaseMultimodalProbe) Description() string {
	return p.ProbeDescription
}

// Goal returns the probe's goal.
func (p *BaseMultimodalProbe) Goal() string {
	return p.ProbeGoal
}

// GetPrimaryDetector returns the recommended detector.
func (p *BaseMultimodalProbe) GetPrimaryDetector() string {
	return p.PrimaryDetector
}

// GetImages returns all images used by this probe, aggregated from all prompts.
func (p *BaseMultimodalProbe) GetImages() []attempt.Image {
	var imgs []attempt.Image
	for _, mp := range p.Prompts {
		imgs = append(imgs, mp.Images...)
	}
	return imgs
}

// GetAudio returns nil; multimodal image probes do not use audio.
func (p *BaseMultimodalProbe) GetAudio() []attempt.Audio {
	return nil
}

// GetPrompts returns the text portion of each prompt.
func (p *BaseMultimodalProbe) GetPrompts() []string {
	prompts := make([]string, len(p.Prompts))
	for i, mp := range p.Prompts {
		prompts[i] = mp.Text
	}
	return prompts
}
