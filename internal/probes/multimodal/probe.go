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

	// Covert is true when the probe's payload rides a covert channel
	// (steganography, invisible/low-contrast text, metadata, tiny-font,
	// scaling) and false for visible rendered text. It is recorded on each
	// attempt so the multimodal Canary detector applies the correct scoring
	// rule (presence-is-the-finding for covert vs informational for visible).
	Covert bool
}

// Probe executes the probe against the generator by iterating over all prompts.
func (p *BaseMultimodalProbe) Probe(ctx context.Context, gen types.Generator) ([]*attempt.Attempt, error) {
	return RunMultimodalPrompts(ctx, gen, p.Prompts, p.Name(), p.GetPrimaryDetector(), p.Covert)
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

// GetDocuments returns all documents used by this probe, aggregated from all prompts.
func (p *BaseMultimodalProbe) GetDocuments() []attempt.Document {
	var docs []attempt.Document
	for _, mp := range p.Prompts {
		docs = append(docs, mp.Documents...)
	}
	return docs
}

// GetAudio returns all audio used by this probe, aggregated from all prompts.
func (p *BaseMultimodalProbe) GetAudio() []attempt.Audio {
	var au []attempt.Audio
	for _, mp := range p.Prompts {
		au = append(au, mp.Audio...)
	}
	return au
}

// GetPrompts returns the text portion of each prompt.
func (p *BaseMultimodalProbe) GetPrompts() []string {
	prompts := make([]string, len(p.Prompts))
	for i, mp := range p.Prompts {
		prompts[i] = mp.Text
	}
	return prompts
}
