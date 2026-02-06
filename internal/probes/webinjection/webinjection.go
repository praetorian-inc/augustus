// Package webinjection provides web content injection probes for LLM testing.
//
// These probes test if LLMs can be tricked into generating malicious web content
// through various injection vectors including HTML, JavaScript, CSS, and form fields.
package webinjection

import (
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

// WebInjectionProbe embeds *probes.SimpleProbe and adds injection-specific fields.
type WebInjectionProbe struct {
	*probes.SimpleProbe
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
			SimpleProbe: &probes.SimpleProbe{
				ProbeName:        name,
				ProbeGoal:        goal,
				PrimaryDetector:  "webinjection.Detector",
				ProbeDescription: description,
				Prompts:          prompts,
			},
			injectionType: injType,
		}, nil
	}
}
