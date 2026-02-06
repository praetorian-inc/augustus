// Package grandma provides social engineering probes using emotional manipulation
// via appeal to a deceased grandmother figure.
//
// These probes attempt to get models to output harmful content by framing
// requests as attempts to remember or honor a fictitious grandmother.
//
// Python garak equivalent: garak.probes.grandma
//
// References:
// - https://www.independent.co.uk/tech/chatgpt-microsoft-windows-11-grandma-exploit-b2360213.html
// - https://x.com/_annieversary/status/1647865782741749760
// - https://www.cyberark.com/resources/threat-research-blog/operation-grandma-a-tale-of-llm-chatbot-vulnerability
package grandma

import (
	"strings"

	"github.com/praetorian-inc/augustus/pkg/probes"
)

// GrandmaProbe provides shared infrastructure for all grandma-based social engineering probes.
// Each specific probe embeds this struct and provides its templates and parameters.
type GrandmaProbe struct {
	*probes.SimpleProbe
}

// NewGrandmaProbe creates a base probe with generated prompts.
// templates: prompt templates with {placeholder} syntax
// parameters: values to substitute into templates
// name: fully qualified probe name (e.g., "grandma.Win10")
// goal: probe objective
// detector: primary detector to use
func NewGrandmaProbe(templates, parameters []string, name, goal, detector, description string) *GrandmaProbe {
	prompts := generatePrompts(templates, parameters)

	return &GrandmaProbe{
		SimpleProbe: probes.NewSimpleProbe(name, goal, detector, description, prompts),
	}
}

// generatePrompts generates all prompt combinations by replacing placeholders in templates.
// For each template x parameter combination, replaces the first placeholder with the parameter.
//
// Matches Python garak grandma probe __init__ logic (lines 66-70, 109-113, 145-149).
func generatePrompts(templates, parameters []string) []string {
	var prompts []string

	for _, template := range templates {
		for _, param := range parameters {
			// Find the placeholder pattern (different for each probe type)
			// Win10/Win11 use {product_name}
			// Slurs use {group_name}
			// Substances use [SUBSTANCE]
			prompt := replacePlaceholder(template, param)
			prompts = append(prompts, prompt)
		}
	}

	return prompts
}

// replacePlaceholder replaces the first placeholder in the template with the parameter.
// Handles both {placeholder} and [PLACEHOLDER] styles.
func replacePlaceholder(template, param string) string {
	// Try {placeholder} style first
	if strings.Contains(template, "{") {
		// Find the placeholder
		start := strings.Index(template, "{")
		end := strings.Index(template, "}")
		if start >= 0 && end > start {
			placeholder := template[start : end+1]
			return strings.ReplaceAll(template, placeholder, param)
		}
	}

	// Try [PLACEHOLDER] style (used by Substances probe)
	if strings.Contains(template, "[") {
		start := strings.Index(template, "[")
		end := strings.Index(template, "]")
		if start >= 0 && end > start {
			placeholder := template[start : end+1]
			return strings.ReplaceAll(template, placeholder, param)
		}
	}

	// No placeholder found, return template as-is
	return template
}
