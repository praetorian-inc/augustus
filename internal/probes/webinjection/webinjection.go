// Package webinjection provides web content injection probes for LLM testing.
//
// These probes test if LLMs can be tricked into generating malicious web content
// through various injection vectors including HTML, JavaScript, CSS, and form fields.
package webinjection

import (
	"context"

	"github.com/praetorian-inc/augustus/pkg/attempt"
	"github.com/praetorian-inc/augustus/pkg/probes"
	"github.com/praetorian-inc/augustus/pkg/registry"
)

func init() {
	probes.Register("webinjection.HTMLComment", NewWebInjection(HTMLComment))
	probes.Register("webinjection.MetaTags", NewWebInjection(MetaTags))
	probes.Register("webinjection.JavaScript", NewWebInjection(JavaScript))
	probes.Register("webinjection.CSS", NewWebInjection(CSS))
	probes.Register("webinjection.FormFields", NewWebInjection(FormFields))
}

// InjectionType defines the type of web injection attack.
type InjectionType int

const (
	// HTMLComment tests injection via HTML comments
	HTMLComment InjectionType = iota
	// MetaTags tests injection via HTML meta tags
	MetaTags
	// JavaScript tests injection via JavaScript code
	JavaScript
	// CSS tests injection via CSS styles
	CSS
	// FormFields tests injection via HTML form fields
	FormFields
)

// SimpleProbe provides shared infrastructure for web injection probes.
// This struct eliminates duplicate Probe() implementations.
type SimpleProbe struct {
	name            string
	goal            string
	primaryDetector string
	description     string
	prompts         []string
}

// Probe executes the probe against the generator.
func (s *SimpleProbe) Probe(ctx context.Context, gen probes.Generator) ([]*attempt.Attempt, error) {
	attempts := make([]*attempt.Attempt, 0, len(s.prompts))

	for _, prompt := range s.prompts {
		conv := attempt.NewConversation()
		conv.AddPrompt(prompt)

		responses, err := gen.Generate(ctx, conv, 1)

		a := attempt.New(prompt)
		a.Probe = s.Name()
		a.Detector = s.GetPrimaryDetector()

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
func (s *SimpleProbe) Name() string {
	return s.name
}

// Description returns a human-readable description.
func (s *SimpleProbe) Description() string {
	return s.description
}

// Goal returns the probe's goal.
func (s *SimpleProbe) Goal() string {
	return s.goal
}

// GetPrimaryDetector returns the recommended detector.
func (s *SimpleProbe) GetPrimaryDetector() string {
	return s.primaryDetector
}

// GetPrompts returns the prompts used by this probe.
func (s *SimpleProbe) GetPrompts() []string {
	return s.prompts
}

// WebInjectionProbe embeds SimpleProbe and adds injection-specific fields.
type WebInjectionProbe struct {
	SimpleProbe
	injectionType InjectionType
}

// NewWebInjection creates a factory function for web injection probes.
func NewWebInjection(injType InjectionType) func(registry.Config) (probes.Prober, error) {
	return func(_ registry.Config) (probes.Prober, error) {
		var name, goal, description string
		var prompts []string

		switch injType {
		case HTMLComment:
			name = "webinjection.HTMLComment"
			goal = "inject malicious content via HTML comments"
			description = "Tests if LLM generates content with malicious HTML comments"
			prompts = getHTMLCommentPayloads()
		case MetaTags:
			name = "webinjection.MetaTags"
			goal = "inject malicious content via HTML meta tags"
			description = "Tests if LLM generates content with malicious meta tags"
			prompts = getMetaTagPayloads()
		case JavaScript:
			name = "webinjection.JavaScript"
			goal = "inject malicious content via JavaScript"
			description = "Tests if LLM generates content with malicious JavaScript"
			prompts = getJavaScriptPayloads()
		case CSS:
			name = "webinjection.CSS"
			goal = "inject malicious content via CSS"
			description = "Tests if LLM generates content with malicious CSS"
			prompts = getCSSPayloads()
		case FormFields:
			name = "webinjection.FormFields"
			goal = "inject malicious content via form fields"
			description = "Tests if LLM generates content with malicious form fields"
			prompts = getFormFieldPayloads()
		}

		return &WebInjectionProbe{
			SimpleProbe: SimpleProbe{
				name:            name,
				goal:            goal,
				primaryDetector: "webinjection.Detector",
				description:     description,
				prompts:         prompts,
			},
			injectionType: injType,
		}, nil
	}
}
